"""Opens a v2 vault and lists its files.

usage: python3 open_vault.py VAULT_DIR (--password PW | --recovery-key HZRK-...) [--show]
       python3 open_vault.py --check-vectors [FIXTURE_DIR]

--check-vectors opens the fixture vault with the password and with the
recovery key and recomputes every known-answer vector in vectors.json.
"""

import argparse
import hashlib
import json
import os
import sys
import uuid

import hzv2


def list_vault(root, password=None, recovery_key=None, show=False):
    opened = hzv2.open_vault(root, password=password, recovery_key=recovery_key)
    print("vault", hzv2.uuid_upper(opened["vaultID"]), "role", opened["role"],
          "generation", opened["metadata"]["generation"])
    for name, data in opened["files"]:
        print("  %-20s %8d bytes  sha256 %s" % (name, len(data), hashlib.sha256(data).hexdigest()))
        if show:
            print("    ", data[:64])
    return opened


def check_vectors(fixture):
    with open(os.path.join(fixture, "vectors.json"), encoding="utf-8") as handle:
        v = json.load(handle)
    fv = v["fixtureVault"]
    root = os.path.join(fixture, fv["directory"])
    expected = [(f["name"], bytes.fromhex(f["contentHex"])) for f in fv["files"]]

    for kwargs in ({"password": fv["password"]}, {"recovery_key": fv["recoveryKey"]}):
        opened = list_vault(root, **kwargs)
        assert opened["files"] == expected, kwargs
        assert opened["role"] == fv["role"]
        assert opened["masterKey"].hex() == fv["masterKeyHex"]
        assert hzv2.uuid_upper(opened["vaultID"]) == fv["vaultID"]
        assert opened["metadata"]["accessID"] == fv["accessID"]
        assert opened["metadata"]["generation"] == fv["metadataGeneration"]

    master = bytes.fromhex(fv["masterKeyHex"])
    _, content = hzv2.read_metadata(root, master)
    assert content.hex() == fv["metadataJSONHex"]
    assert hzv2.swift_json(json.loads(content), escape_slashes=True) == content
    env_bytes = open(os.path.join(root, hzv2.ENVELOPE_NAME), "rb").read()
    assert hzv2.swift_json(json.loads(env_bytes), escape_slashes=False) == env_bytes

    try:
        hzv2.open_vault(root, password="wrong password")
        raise AssertionError("wrong password opened the vault")
    except hzv2.FormatError:
        pass

    k = v["passwordKDF"]
    assert hzv2.derive_slot_key(k["password"], bytes.fromhex(k["saltHex"]), k["operationsLimit"],
                                k["memoryLimit"]).hex() == k["keyHex"]

    s = v["slotUnwrap"]
    env = hzv2.read_envelope(root)
    assert env["accessSlots"][0]["wrappedPayload"] == hzv2.b64(bytes.fromhex(s["wrappedPayloadHex"]))
    role, key = hzv2.unwrap_slot(env["accessSlots"][0], k["password"], uuid.UUID(s["vaultID"]))
    assert role == s["role"] and key.hex() == s["masterKeyHex"]
    assert hzv2.unwrap_slot(env["accessSlots"][1], k["password"], uuid.UUID(s["vaultID"])) is None

    d = v["domainKeys"]
    ikm = bytes.fromhex(d["inputKeyHex"])
    for field, info in (("namespaceV2Hex", hzv2.INFO_NAMESPACE), ("recoveryNamespaceV2Hex", hzv2.INFO_RECOVERY_NAMESPACE),
                        ("poolObjectV2Hex", hzv2.INFO_POOL_OBJECT), ("indexV1Hex", hzv2.INFO_INDEX_V1),
                        ("objectV1Hex", hzv2.INFO_OBJECT_V1)):
        assert hzv2.hkdf(ikm, info).hex() == d[field], field

    r = v["recoveryKey"]
    secret = bytes.fromhex(r["secretHex"])
    assert hzv2.format_recovery_key(secret) == r["displayKey"]
    for text in r["acceptedInputs"]:
        assert hzv2.recovery_secret_from(text) == secret
    for text in r["rejectedInputs"]:
        try:
            hzv2.recovery_secret_from(text)
            raise AssertionError("accepted " + text)
        except hzv2.FormatError:
            pass
    assert hzv2.recovery_anchor_name(secret, uuid.UUID(r["vaultID"])) == r["anchorName"]
    kind, payload = hzv2.open_object(hzv2.read_pool_file(root, r["anchorName"]), secret, r["anchorName"])
    assert kind == hzv2.KIND_RECOVERY and payload.hex() == fv["recoveryPayloadJSONHex"]

    m = v["metadataAnchor"]
    assert hzv2.metadata_anchor_name(bytes.fromhex(m["masterKeyHex"])) == m["name"]

    p = v["poolObject"]
    envelope = bytes.fromhex(p["envelopeHex"])
    assert len(envelope) == p["paddedPlaintextByteCount"] + hzv2.POOL_OVERHEAD
    kind, content = hzv2.open_object(envelope, bytes.fromhex(p["keyMaterialHex"]), p["objectName"])
    assert kind == p["kind"] and content.hex() == p["contentHex"]
    try:
        hzv2.open_object(envelope, bytes.fromhex(p["keyMaterialHex"]), p["otherObjectName"])
        raise AssertionError("name binding not enforced")
    except hzv2.FormatError:
        pass

    mo = v["manifestObject"]
    kind, content = hzv2.open_object(bytes.fromhex(mo["envelopeHex"]), bytes.fromhex(mo["keyMaterialHex"]), mo["objectName"])
    assert kind == hzv2.KIND_MANIFEST and content.hex() == mo["contentJSONHex"]
    manifest = json.loads(content)
    assert manifest["fileID"] == mo["fileID"] and manifest["chunks"] == mo["chunks"]
    assert hzv2.unb64(manifest["sha256Digest"]).hex() == mo["sha256DigestHex"]

    for c in v["coverNames"]:
        assert hzv2.cover_name(bytes.fromhex(c["masterKeyHex"]), c["bucket"], c["index"]) == c["name"]
    for t in v["dataPaddingTargets"]:
        assert hzv2.data_padding_target(t["contentByteCount"]) == t["plaintextByteCount"]
    for t in v["metadataPaddingTargets"]:
        assert hzv2.metadata_padding_target(t["encodedByteCount"]) == t["plaintextByteCount"]
    print("all vectors OK")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("vault", nargs="?")
    parser.add_argument("--password")
    parser.add_argument("--recovery-key")
    parser.add_argument("--show", action="store_true")
    parser.add_argument("--check-vectors", action="store_true")
    args = parser.parse_args()
    if args.check_vectors:
        here = os.path.dirname(os.path.abspath(__file__))
        default = os.path.join(here, "..", "..", "Tests", "HanzalaomatorCoreTests", "Fixtures", "v2-format-vectors")
        check_vectors(os.path.abspath(args.vault or default))
        return
    if not args.vault or (args.password is None) == (args.recovery_key is None):
        parser.error("give a vault directory and exactly one of --password / --recovery-key")
    list_vault(args.vault, args.password, args.recovery_key, args.show)


if __name__ == "__main__":
    sys.exit(main())
