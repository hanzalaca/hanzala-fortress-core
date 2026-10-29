"""Independent reference implementation of the Hanzalaomator v2 vault format.

Written from Docs/V2-VAULT-FORMAT-SPEC.md only (section numbers in comments).
Requires PyNaCl (libsodium). Not used by the app.
"""

import base64
import datetime as _dt
import hashlib
import hmac
import json
import os
import uuid

from nacl import bindings as nb

# §12 constants
ENVELOPE_NAME = "vault.hanzala"
POOL_DIR = "objects"
ENVELOPE_FORMAT_VERSION = 2
SLOT_COUNT = 2
SLOT_PAYLOAD_VERSION = 2
SLOT_PAYLOAD_SIZE = 70
ROLE_VISIBLE = 1
ROLE_CONCEALED = 2
KDF_ALGORITHM = "argon2id13"
SALT_BYTES = 16
OPSLIMIT_MODERATE = 3
MEMLIMIT_MODERATE = 268435456
OPSLIMIT_SENSITIVE = 4
MEMLIMIT_SENSITIVE = 1073741824
MAX_ENVELOPE_FILE = 1024 * 1024

POOL_MAGIC = b"HZOBJ003"
POOL_PAYLOAD_VERSION = 1
POOL_HEADER = 10
POOL_OVERHEAD = 8 + 24 + 16
MAX_POOL_PLAINTEXT = 16 * 1024 * 1024
KIND_METADATA, KIND_DATA, KIND_PADDING, KIND_MANIFEST, KIND_RECOVERY = 1, 2, 3, 4, 5
BUCKETS = [4096, 16384, 65536, 262144, 1048576, 4194304, 16777216]
RECOVERY_ANCHOR_PLAINTEXT = 4096
FIXED_METADATA_PLAINTEXT = 1048576
CHUNK_PLAINTEXT = 4 * 1024 * 1024
CHUNK_CONTENT = CHUNK_PLAINTEXT - POOL_HEADER
MAX_SINGLE_CONTENT = MAX_POOL_PLAINTEXT - POOL_HEADER

INFO_NAMESPACE = b"hanzala/namespace/v2"
INFO_RECOVERY_NAMESPACE = b"hanzala/recovery-namespace/v2"
INFO_POOL_OBJECT = b"hanzala/pool-object/v2"
INFO_INDEX_V1 = b"hanzala/index/v1"
INFO_OBJECT_V1 = b"hanzala/object/v1"
LABEL_INDEX_ANCHOR = b"hanzala/v2/index-anchor"
LABEL_RECOVERY_ANCHOR = b"hanzala/v2/recovery-anchor"
LABEL_COVER_SLOT = b"hanzala/v2/cover-slot"

METADATA_FORMAT_VERSION = 1
RECOVERY_PAYLOAD_FORMAT_VERSION = 1
MANIFEST_FORMAT_VERSION = 1


class FormatError(Exception):
    pass


# §1 primitives

def hkdf(ikm: bytes, info: bytes) -> bytes:
    if len(ikm) != 32:
        raise FormatError("HKDF input key must be 32 bytes")
    prk = hmac.new(b"\x00" * 32, ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def uuid_upper(u: uuid.UUID) -> str:
    return str(u).upper()


def uuid_lower(u: uuid.UUID) -> str:
    return str(u).lower()


def is_object_name(name: str) -> bool:
    return len(name) == 64 and all(c in "0123456789abcdef" for c in name)


# §9 JSON

def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def iso_date(when: _dt.datetime) -> str:
    return when.astimezone(_dt.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_date(text: str) -> _dt.datetime:
    return _dt.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_dt.timezone.utc)


def swift_json(value, escape_slashes: bool) -> bytes:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if escape_slashes:
        text = text.replace("/", "\\/")
    return text.encode("utf-8")


# §4 envelope

def derive_slot_key(password: str, salt: bytes, opslimit: int, memlimit: int) -> bytes:
    if not (0 < opslimit <= OPSLIMIT_SENSITIVE and 0 < memlimit <= MEMLIMIT_SENSITIVE):
        raise FormatError("KDF parameters out of range")
    if len(salt) != SALT_BYTES:
        raise FormatError("bad salt length")
    return nb.crypto_pwhash_alg(32, password.encode("utf-8"), salt, opslimit, memlimit,
                                nb.crypto_pwhash_ALG_ARGON2ID13)


def slot_payload(role: int, vault_id: uuid.UUID, master_key: bytes) -> bytes:
    payload = bytes([SLOT_PAYLOAD_VERSION, role]) + uuid_lower(vault_id).encode("ascii") + master_key
    assert len(payload) == SLOT_PAYLOAD_SIZE
    return payload


def make_slot(rng, password, role, vault_id, master_key, opslimit, memlimit):
    salt = rng(SALT_BYTES)
    key = derive_slot_key(password, salt, opslimit, memlimit)
    nonce = rng(24)
    wrapped = nonce + nb.crypto_secretbox_easy(slot_payload(role, vault_id, master_key), nonce, key)
    return {
        "kdf": {"algorithm": KDF_ALGORITHM, "memoryLimit": memlimit,
                "operationsLimit": opslimit, "salt": b64(salt)},
        "wrappedPayload": b64(wrapped),
    }


def unwrap_slot(slot, password: str, vault_id: uuid.UUID):
    """Returns (role, master_key) or None."""
    kdf = slot["kdf"]
    try:
        if kdf["algorithm"] != KDF_ALGORITHM:
            return None
        key = derive_slot_key(password, unb64(kdf["salt"]), int(kdf["operationsLimit"]), int(kdf["memoryLimit"]))
        wrapped = unb64(slot["wrappedPayload"])
        payload = nb.crypto_secretbox_open_easy(wrapped[24:], wrapped[:24], key)
    except Exception:
        return None
    if len(payload) != SLOT_PAYLOAD_SIZE or payload[0] != SLOT_PAYLOAD_VERSION or payload[1] not in (1, 2):
        return None
    try:
        embedded = uuid.UUID(payload[2:38].decode("ascii"))
    except Exception:
        return None
    if embedded != vault_id:
        return None
    return payload[1], payload[38:]


def encode_envelope(vault_id, created_at, slots) -> bytes:
    return swift_json({
        "accessSlots": slots,
        "createdAt": iso_date(created_at),
        "formatVersion": ENVELOPE_FORMAT_VERSION,
        "vaultID": uuid_upper(vault_id),
    }, escape_slashes=False)


def read_envelope(root):
    path = os.path.join(root, ENVELOPE_NAME)
    if os.path.islink(path) or not os.path.isfile(path):
        raise FormatError("missing envelope")
    with open(path, "rb") as handle:
        data = handle.read(MAX_ENVELOPE_FILE + 1)
    if len(data) > MAX_ENVELOPE_FILE:
        raise FormatError("envelope too large")
    env = json.loads(data.decode("utf-8"))
    if env.get("formatVersion") != ENVELOPE_FORMAT_VERSION or len(env.get("accessSlots", [])) != SLOT_COUNT:
        raise FormatError("not a v2 envelope")
    env["vaultID"] = uuid.UUID(env["vaultID"])
    return env


def unlock(env, password: str):
    matches = [m for m in (unwrap_slot(s, password, env["vaultID"]) for s in env["accessSlots"]) if m]
    if len(matches) != 1:
        raise FormatError("wrong password" if not matches else "ambiguous password")
    return matches[0]


# §5 names

def metadata_anchor_name(master_key: bytes) -> str:
    return hmac_sha256(hkdf(master_key, INFO_NAMESPACE), LABEL_INDEX_ANCHOR).hex()


def recovery_anchor_name(recovery_secret: bytes, vault_id: uuid.UUID) -> str:
    msg = LABEL_RECOVERY_ANCHOR + b"\x00" + uuid_lower(vault_id).encode("ascii")
    return hmac_sha256(hkdf(recovery_secret, INFO_RECOVERY_NAMESPACE), msg).hex()


def cover_name(master_key: bytes, bucket: int, index: int) -> str:
    msg = LABEL_COVER_SLOT + b"\x00" + bucket.to_bytes(8, "big") + index.to_bytes(8, "big")
    return hmac_sha256(hkdf(master_key, INFO_NAMESPACE), msg).hex()


# §6 pool objects

def seal_object(rng, kind, content, key_material, name, plaintext_size=None):
    if not is_object_name(name):
        raise FormatError("invalid object name")
    minimum = POOL_HEADER + len(content)
    target = minimum if plaintext_size is None else plaintext_size
    if target < minimum or target > MAX_POOL_PLAINTEXT:
        raise FormatError("bad padding target")
    plaintext = bytes([POOL_PAYLOAD_VERSION, kind]) + len(content).to_bytes(8, "big") + content
    plaintext += rng(target - len(plaintext))
    nonce = rng(24)
    ad = POOL_MAGIC + b"\x00" + name.encode("ascii")
    key = hkdf(key_material, INFO_POOL_OBJECT)
    return POOL_MAGIC + nonce + nb.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, ad, nonce, key)


def open_object(envelope: bytes, key_material: bytes, name: str):
    if not is_object_name(name):
        raise FormatError("invalid object name")
    if not (POOL_OVERHEAD + POOL_HEADER <= len(envelope) <= POOL_OVERHEAD + MAX_POOL_PLAINTEXT):
        raise FormatError("bad object size")
    if envelope[:8] != POOL_MAGIC:
        raise FormatError("bad magic")
    ad = POOL_MAGIC + b"\x00" + name.encode("ascii")
    key = hkdf(key_material, INFO_POOL_OBJECT)
    try:
        plaintext = nb.crypto_aead_xchacha20poly1305_ietf_decrypt(envelope[32:], ad, envelope[8:32], key)
    except Exception:
        raise FormatError("authentication failed")
    if len(plaintext) < POOL_HEADER or plaintext[0] != POOL_PAYLOAD_VERSION:
        raise FormatError("bad payload version")
    kind = plaintext[1]
    if kind not in (1, 2, 3, 4, 5):
        raise FormatError("bad kind")
    length = int.from_bytes(plaintext[2:10], "big")
    if length > len(plaintext) - POOL_HEADER:
        raise FormatError("bad logical length")
    return kind, plaintext[10:10 + length]


def bucket_for(minimum: int) -> int:
    for bucket in BUCKETS:
        if bucket >= minimum:
            return bucket
    raise FormatError("too large")


def data_padding_target(content_length: int) -> int:
    if content_length > MAX_SINGLE_CONTENT:
        raise FormatError("content too large for one object")
    return bucket_for(POOL_HEADER + content_length)


def metadata_padding_target(json_length: int) -> int:
    return bucket_for(POOL_HEADER + json_length)


def read_pool_file(root, name):
    path = os.path.join(root, POOL_DIR, name)
    if os.path.islink(path) or not os.path.isfile(path):
        raise FormatError("missing object " + name)
    with open(path, "rb") as handle:
        return handle.read()


def write_pool_file(root, name, data):
    with open(os.path.join(root, POOL_DIR, name), "wb") as handle:
        handle.write(data)


# §7 recovery key

def format_recovery_key(secret: bytes) -> str:
    body = secret.hex().upper()
    return "HZRK-" + "-".join(body[i:i + 4] for i in range(0, 64, 4))


def recovery_secret_from(text: str) -> bytes:
    compact = "".join(text.upper().replace("-", " ").split())
    if not compact.startswith("HZRK"):
        raise FormatError("invalid recovery key")
    body = compact[4:]
    if len(body) != 64 or any(c not in "0123456789ABCDEF" for c in body):
        raise FormatError("invalid recovery key")
    return bytes.fromhex(body)


def recovery_payload_json(vault_id, access_id, role, master_key) -> bytes:
    return swift_json({
        "accessID": uuid_upper(access_id),
        "formatVersion": RECOVERY_PAYLOAD_FORMAT_VERSION,
        "masterKey": b64(master_key),
        "roleRawValue": role,
        "vaultID": uuid_upper(vault_id),
    }, escape_slashes=False)


def recover(root, env, recovery_key: str):
    secret = recovery_secret_from(recovery_key)
    name = recovery_anchor_name(secret, env["vaultID"])
    kind, content = open_object(read_pool_file(root, name), secret, name)
    if kind != KIND_RECOVERY:
        raise FormatError("not a recovery anchor")
    payload = json.loads(content)
    master_key = unb64(payload["masterKey"])
    if (payload["formatVersion"] != RECOVERY_PAYLOAD_FORMAT_VERSION
            or uuid.UUID(payload["vaultID"]) != env["vaultID"]
            or len(master_key) != 32 or payload["roleRawValue"] not in (1, 2)):
        raise FormatError("invalid recovery anchor")
    return payload["roleRawValue"], master_key, uuid.UUID(payload["accessID"])


# §8 metadata

def entry_json(entry_id, object_name, original_name, length, created_at, auxiliary=()):
    return {
        "auxiliaryObjectNames": list(auxiliary),
        "createdAt": iso_date(created_at),
        "id": uuid_upper(entry_id),
        "logicalByteCount": length,
        "opaqueObjectName": object_name,
        "originalName": original_name,
    }


def metadata_json(access_id, generation, entries, budget, usage) -> bytes:
    return swift_json({
        "accessID": uuid_upper(access_id),
        "budget": budget,
        "entries": entries,
        "formatVersion": METADATA_FORMAT_VERSION,
        "generation": generation,
        "pendingChunkImports": [],
        "pendingImports": [],
        "pendingRemovals": [],
        "tombstonedObjectNames": [],
        "usage": usage,
    }, escape_slashes=True)


def validate_metadata(meta):
    # Read-only subset of the §8.2 checks: it skips the cross-transaction
    # ownership, pending chunk manifest and fixed-capacity checks. An
    # implementation that writes vaults must perform all of §8.2.
    if meta["formatVersion"] != METADATA_FORMAT_VERSION:
        raise FormatError("unsupported metadata version")
    entries = meta["entries"]
    names = set()
    for entry in entries:
        for name in [entry["opaqueObjectName"]] + entry.get("auxiliaryObjectNames", []):
            if not is_object_name(name) or name in names:
                raise FormatError("bad object name in metadata")
            names.add(name)
        original = entry["originalName"]
        if original in ("", ".", "..") or any(c in original for c in "/\\\x00"):
            raise FormatError("bad original name")
    usage = meta["usage"]
    if usage["logicalBytes"] != sum(e["logicalByteCount"] for e in entries) or usage["objectCount"] != len(entries):
        raise FormatError("usage mismatch")
    budget = meta["budget"]
    pending = sum(p["logicalByteCount"] for p in meta.get("pendingImports", []) + meta.get("pendingChunkImports", [])
                  + meta.get("pendingRemovals", []))
    if usage["logicalBytes"] + pending > budget["totalBytes"] - budget["reserveBytes"] - budget["safetyMarginBytes"]:
        raise FormatError("usage exceeds budget")


def read_metadata(root, master_key):
    name = metadata_anchor_name(master_key)
    kind, content = open_object(read_pool_file(root, name), master_key, name)
    if kind != KIND_METADATA:
        raise FormatError("not a metadata anchor")
    meta = json.loads(content.decode("utf-8"))
    validate_metadata(meta)
    return meta, content


# §10 manifests

def manifest_json(file_id, chunks, digest) -> bytes:
    return swift_json({
        "chunks": [{"logicalByteCount": n, "opaqueObjectName": name} for name, n in chunks],
        "fileID": uuid_upper(file_id),
        "formatVersion": MANIFEST_FORMAT_VERSION,
        "logicalByteCount": sum(n for _, n in chunks),
        "sha256Digest": b64(digest),
    }, escape_slashes=False)


def read_entry(root, master_key, entry) -> bytes:
    if not entry.get("auxiliaryObjectNames"):
        name = entry["opaqueObjectName"]
        kind, content = open_object(read_pool_file(root, name), master_key, name)
        if kind != KIND_DATA or len(content) != entry["logicalByteCount"]:
            raise FormatError("data object mismatch")
        return content
    name = entry["opaqueObjectName"]
    kind, content = open_object(read_pool_file(root, name), master_key, name)
    if kind != KIND_MANIFEST:
        raise FormatError("not a manifest")
    manifest = json.loads(content)
    if (manifest["formatVersion"] != MANIFEST_FORMAT_VERSION
            or uuid.UUID(manifest["fileID"]) != uuid.UUID(entry["id"])
            or manifest["logicalByteCount"] != entry["logicalByteCount"]
            or [c["opaqueObjectName"] for c in manifest["chunks"]] != entry["auxiliaryObjectNames"]):
        raise FormatError("manifest mismatch")
    out = b""
    for chunk in manifest["chunks"]:
        kind, part = open_object(read_pool_file(root, chunk["opaqueObjectName"]), master_key, chunk["opaqueObjectName"])
        if kind != KIND_DATA or len(part) != chunk["logicalByteCount"]:
            raise FormatError("chunk mismatch")
        out += part
    if hashlib.sha256(out).digest() != unb64(manifest["sha256Digest"]):
        raise FormatError("digest mismatch")
    return out


# §8.3 whole-vault read

def open_vault(root, password=None, recovery_key=None):
    env = read_envelope(root)
    if password is not None:
        role, master_key = unlock(env, password)
        meta, _ = read_metadata(root, master_key)
    else:
        role, master_key, access_id = recover(root, env, recovery_key)
        meta, _ = read_metadata(root, master_key)
        if uuid.UUID(meta["accessID"]) != access_id:
            raise FormatError("recovery anchor does not match metadata")
    files = [(e["originalName"], read_entry(root, master_key, e)) for e in meta["entries"]]
    return {"vaultID": env["vaultID"], "role": role, "masterKey": master_key, "metadata": meta, "files": files}
