"""Deterministically writes the v2 fixture vault and known-answer vectors.

usage: python3 generate_fixture.py [OUTPUT_DIR]
default OUTPUT_DIR: Tests/HanzalaomatorCoreTests/Fixtures/v2-format-vectors
"""

import datetime as dt
import hashlib
import json
import os
import shutil
import sys
import uuid

import hzv2

SEED = b"hanzalaomator/v2-format-vectors/seed-1"
PASSWORD = "correct horse battery staple"
RECOVERY_SECRET = bytes(range(32))
# Small Argon2id cost: Swift accepts any 0 < ops <= 4, 0 < mem <= 1 GiB (spec §4.1).
OPSLIMIT = 2
MEMLIMIT = 8 * 1024 * 1024
BUDGET = {"reserveBytes": 1024 * 1024, "safetyMarginBytes": 0, "totalBytes": 8 * 1024 * 1024}
CREATED_AT = dt.datetime(2026, 1, 1, 0, 0, 0, tzinfo=dt.timezone.utc)

FILES = [
    ("hello world.txt", b"Hello from the Hanzalaomator v2 format vectors.\n"),
    ("pixel.bin", bytes(range(256)) * 2),
    ("notes-16k.dat", bytes((i * 31) % 251 for i in range(5000))),
]


class DeterministicRandom:
    def __init__(self, seed):
        self.seed = seed
        self.counter = 0

    def __call__(self, n):
        self.counter += 1
        return hashlib.shake_256(self.seed + self.counter.to_bytes(8, "big")).digest(n)

    def uuid4(self):
        return uuid.UUID(bytes=self(16), version=4)

    def name(self):
        return self(32).hex()


def build_vault(root, rng):
    vault_id = rng.uuid4()
    visible_key = rng(32)
    dummy_key = rng(32)
    dummy_password = hzv2.b64(rng(32))
    dummy_recovery = rng(32)

    slots = [
        hzv2.make_slot(rng, PASSWORD, hzv2.ROLE_VISIBLE, vault_id, visible_key, OPSLIMIT, MEMLIMIT),
        hzv2.make_slot(rng, dummy_password, hzv2.ROLE_CONCEALED, vault_id, dummy_key, OPSLIMIT, MEMLIMIT),
    ]
    os.makedirs(os.path.join(root, hzv2.POOL_DIR))
    usage0 = {"logicalBytes": 0, "objectCount": 0}

    access_ids = []
    for key in (visible_key, dummy_key):
        access_id = rng.uuid4()
        access_ids.append(access_id)
        content = hzv2.metadata_json(access_id, 0, [], BUDGET, usage0)
        name = hzv2.metadata_anchor_name(key)
        hzv2.write_pool_file(root, name, hzv2.seal_object(
            rng, hzv2.KIND_METADATA, content, key, name, hzv2.metadata_padding_target(len(content))))

    for secret, key, role, access_id in (
        (RECOVERY_SECRET, visible_key, hzv2.ROLE_VISIBLE, access_ids[0]),
        (dummy_recovery, dummy_key, hzv2.ROLE_CONCEALED, access_ids[1]),
    ):
        name = hzv2.recovery_anchor_name(secret, vault_id)
        content = hzv2.recovery_payload_json(vault_id, access_id, role, key)
        hzv2.write_pool_file(root, name, hzv2.seal_object(
            rng, hzv2.KIND_RECOVERY, content, secret, name, hzv2.RECOVERY_ANCHOR_PLAINTEXT))

    # §13: each import is a pending claim (+1) then finalization (+1).
    entries = []
    for index, (original, data) in enumerate(FILES):
        name = rng.name()
        entry_id = rng.uuid4()
        hzv2.write_pool_file(root, name, hzv2.seal_object(
            rng, hzv2.KIND_DATA, data, visible_key, name, hzv2.data_padding_target(len(data))))
        created = CREATED_AT + dt.timedelta(seconds=60 * (index + 1))
        entries.append(hzv2.entry_json(entry_id, name, original, len(data), created))

    usage = {"logicalBytes": sum(len(d) for _, d in FILES), "objectCount": len(FILES)}
    content = hzv2.metadata_json(access_ids[0], 2 * len(FILES), entries, BUDGET, usage)
    name = hzv2.metadata_anchor_name(visible_key)
    hzv2.write_pool_file(root, name, hzv2.seal_object(
        rng, hzv2.KIND_METADATA, content, visible_key, name, hzv2.metadata_padding_target(len(content))))

    with open(os.path.join(root, hzv2.ENVELOPE_NAME), "wb") as handle:
        handle.write(hzv2.encode_envelope(vault_id, CREATED_AT, slots))

    return {
        "vaultID": vault_id,
        "visibleKey": visible_key,
        "accessID": access_ids[0],
        "slots": slots,
        "entries": entries,
        "metadataJSON": content,
    }


def build_vectors(rng, vault):
    vault_id = vault["vaultID"]
    master_key = vault["visibleKey"]
    slot = vault["slots"][0]
    salt = hzv2.unb64(slot["kdf"]["salt"])
    wrapped = hzv2.unb64(slot["wrappedPayload"])
    slot_key = hzv2.derive_slot_key(PASSWORD, salt, OPSLIMIT, MEMLIMIT)
    recovery_key = hzv2.format_recovery_key(RECOVERY_SECRET)

    pool_name = rng.name()
    pool_content = b"known-answer pool object"
    pool_envelope = hzv2.seal_object(rng, hzv2.KIND_DATA, pool_content, master_key, pool_name, 64)

    manifest_name = rng.name()
    file_id = rng.uuid4()
    # Smallest chunked file: four full chunks plus 31 bytes (spec §10).
    chunks = [(rng.name(), hzv2.CHUNK_CONTENT) for _ in range(4)] + [(rng.name(), 31)]
    digest = hashlib.sha256(b"not the real chunk bytes").digest()
    manifest_content = hzv2.manifest_json(file_id, chunks, digest)
    manifest_envelope = hzv2.seal_object(
        rng, hzv2.KIND_MANIFEST, manifest_content, master_key, manifest_name,
        hzv2.metadata_padding_target(len(manifest_content)))

    recovery_content = hzv2.recovery_payload_json(vault_id, vault["accessID"], hzv2.ROLE_VISIBLE, master_key)

    cover_cases = [(4096, 0), (4096, 1), (65536, 9), (4194304, 250), (16777216, 7)]
    return {
        "comment": "Generated by Scripts/vault_format_reference/generate_fixture.py from Docs/V2-VAULT-FORMAT-SPEC.md. Do not edit by hand.",
        "fixtureVault": {
            "directory": "vault",
            "password": PASSWORD,
            "recoveryKey": recovery_key,
            "vaultID": hzv2.uuid_upper(vault_id),
            "accessID": hzv2.uuid_upper(vault["accessID"]),
            "role": hzv2.ROLE_VISIBLE,
            "masterKeyHex": master_key.hex(),
            "metadataAnchorName": hzv2.metadata_anchor_name(master_key),
            "recoveryAnchorName": hzv2.recovery_anchor_name(RECOVERY_SECRET, vault_id),
            "metadataGeneration": 2 * len(FILES),
            "metadataJSONHex": vault["metadataJSON"].hex(),
            "recoveryPayloadJSONHex": recovery_content.hex(),
            "files": [
                {"name": name, "id": entry["id"], "objectName": entry["opaqueObjectName"],
                 "createdAt": entry["createdAt"], "byteCount": len(data), "contentHex": data.hex(),
                 "sha256Hex": hashlib.sha256(data).hexdigest()}
                for (name, data), entry in zip(FILES, vault["entries"])
            ],
        },
        "passwordKDF": {
            "password": PASSWORD,
            "algorithm": hzv2.KDF_ALGORITHM,
            "saltHex": salt.hex(),
            "operationsLimit": OPSLIMIT,
            "memoryLimit": MEMLIMIT,
            "keyHex": slot_key.hex(),
        },
        "slotUnwrap": {
            "wrappedPayloadHex": wrapped.hex(),
            "payloadHex": hzv2.slot_payload(hzv2.ROLE_VISIBLE, vault_id, master_key).hex(),
            "role": hzv2.ROLE_VISIBLE,
            "vaultID": hzv2.uuid_upper(vault_id),
            "masterKeyHex": master_key.hex(),
        },
        "domainKeys": {
            "inputKeyHex": master_key.hex(),
            "namespaceV2Hex": hzv2.hkdf(master_key, hzv2.INFO_NAMESPACE).hex(),
            "recoveryNamespaceV2Hex": hzv2.hkdf(master_key, hzv2.INFO_RECOVERY_NAMESPACE).hex(),
            "poolObjectV2Hex": hzv2.hkdf(master_key, hzv2.INFO_POOL_OBJECT).hex(),
            "indexV1Hex": hzv2.hkdf(master_key, hzv2.INFO_INDEX_V1).hex(),
            "objectV1Hex": hzv2.hkdf(master_key, hzv2.INFO_OBJECT_V1).hex(),
        },
        "recoveryKey": {
            "displayKey": recovery_key,
            "acceptedInputs": [
                recovery_key.lower(),
                recovery_key.replace("-", ""),
                "  " + recovery_key.replace("-", " ").lower() + "\n",
            ],
            "rejectedInputs": [
                recovery_key[:-1],
                recovery_key.replace("HZRK", "HZRX"),
                recovery_key[:-1] + "G",
            ],
            "secretHex": RECOVERY_SECRET.hex(),
            "vaultID": hzv2.uuid_upper(vault_id),
            "recoveryNamespaceKeyHex": hzv2.hkdf(RECOVERY_SECRET, hzv2.INFO_RECOVERY_NAMESPACE).hex(),
            "anchorName": hzv2.recovery_anchor_name(RECOVERY_SECRET, vault_id),
        },
        "metadataAnchor": {
            "masterKeyHex": master_key.hex(),
            "name": hzv2.metadata_anchor_name(master_key),
        },
        "poolObject": {
            "keyMaterialHex": master_key.hex(),
            "objectName": pool_name,
            "kind": hzv2.KIND_DATA,
            "contentHex": pool_content.hex(),
            "paddedPlaintextByteCount": 64,
            "envelopeHex": pool_envelope.hex(),
            "otherObjectName": rng.name(),
        },
        "manifestObject": {
            "keyMaterialHex": master_key.hex(),
            "objectName": manifest_name,
            "fileID": hzv2.uuid_upper(file_id),
            "logicalByteCount": sum(n for _, n in chunks),
            "chunks": [{"opaqueObjectName": n, "logicalByteCount": c} for n, c in chunks],
            "sha256DigestHex": digest.hex(),
            "contentJSONHex": manifest_content.hex(),
            "envelopeHex": manifest_envelope.hex(),
        },
        "coverNames": [
            {"masterKeyHex": master_key.hex(), "bucket": b, "index": i, "name": hzv2.cover_name(master_key, b, i)}
            for b, i in cover_cases
        ],
        "dataPaddingTargets": [
            {"contentByteCount": n, "plaintextByteCount": hzv2.data_padding_target(n)}
            for n in (0, 4086, 4087, 16374, 16375, 1048566, 1048567, 16777206)
        ],
        "metadataPaddingTargets": [
            {"encodedByteCount": n, "plaintextByteCount": hzv2.metadata_padding_target(n)}
            for n in (0, 4086, 4087, 65526, 65527)
        ],
        "fixedCapacityPlans": [fixed_plan(c) for c in (64 * 1024 * 1024, 1024 * 1024 * 1024)],
    }


def fixed_plan(capacity):
    shares = [(4096, 1, 4096), (16384, 1, 2048), (65536, 2, 1024), (262144, 4, 512),
              (1048576, 8, 512), (16777216, 16, None)]
    counts, used = {}, 0
    for bucket, percent, maximum in shares:
        count = capacity * percent // 100 // bucket
        if maximum is not None:
            count = min(count, maximum)
        counts[bucket] = count
        used += count * bucket
    counts[4194304] = counts.get(4194304, 0) + (capacity - used) // 4194304
    slots = [{"plaintextByteCount": b, "count": c} for b, c in sorted(counts.items()) if c > 0]
    return {"capacityBytes": capacity, "slots": slots}


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    default = os.path.join(here, "..", "..", "Tests", "HanzalaomatorCoreTests", "Fixtures", "v2-format-vectors")
    out = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else default)
    root = os.path.join(out, "vault")
    if os.path.exists(root):
        shutil.rmtree(root)
    os.makedirs(out, exist_ok=True)
    rng = DeterministicRandom(SEED)
    vault = build_vault(root, rng)
    vectors = build_vectors(rng, vault)
    with open(os.path.join(out, "vectors.json"), "w", encoding="utf-8") as handle:
        json.dump(vectors, handle, indent=2, sort_keys=True, ensure_ascii=False)
        handle.write("\n")
    print("wrote", out)


if __name__ == "__main__":
    main()
