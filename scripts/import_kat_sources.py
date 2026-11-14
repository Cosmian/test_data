#!/usr/bin/env python3
"""Convert official known-answer test vectors into JSON files for the KMS tests.

Sources (all already present for a normal build of the workspace):
  - the OpenSSL 3.1.2 tarball in resources/tarballs (the FIPS provider the KMS ships),
  - the RustCrypto `cmac` 0.7.2 and `aes-gcm` 0.10.3 crates in the cargo registry
    (NIST CAVP and Wycheproof data).

Output (default: test_data/kat_sources): aes_cmac.json, aes_gcm.json, aes_gmac.json,
shake256.json. Every record carries its `source`. Reruns are byte-identical.
Standard library only.
"""

import argparse
import glob
import hashlib
import json
import os
import re
import sys
import tarfile

OPENSSL_SHA256 = "a0ce69b8b97ea6a35b96875235aa453b966ba3cba8af2de23657d8b6767d6539"
OPENSSL_DATA = "openssl-3.1.2/test/recipes/30-test_evp_data/"
OPENSSL_MAC = "evpmac_common.txt"
OPENSSL_CIPHER = "evpciph_aes_common.txt"
OPENSSL_MD = "evpmd_sha.txt"
GCM_KEYS = {"Cipher", "Key", "IV", "AAD", "Tag", "Plaintext", "Ciphertext", "NextIV", "Operation", "Result"}


def fatal(message):
    print(f"ERROR: {message}", file=sys.stderr)
    sys.exit(1)


def parse_openssl_stanzas(text):
    """Blank-line separated `Key = Value` stanzas; stanzas with a repeated key are skipped."""
    stanzas = []
    for block in re.split(r"\n\s*\n", text):
        stanza = {}
        duplicate = False
        for line in block.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = (part.strip() for part in line.split("=", 1))
            if value == '""':  # OpenSSL's spelling of an empty value
                value = ""
            if key in stanza:
                duplicate = True
            stanza[key] = value
        if stanza and not duplicate:
            stanzas.append(stanza)
    return stanzas


def read_vlq(data, pos):
    """blobby 0.3 VLQ: 7 bits per byte, big endian, +1 per continuation byte."""
    value = 0
    while True:
        byte = data[pos]
        pos += 1
        value = (value << 7) | (byte & 0x7F)
        if byte & 0x80 == 0:
            return value, pos
        value += 1


def decode_blobby(data):
    """Decode a blobby 0.3 file into a list of byte strings."""
    count, pos = read_vlq(data, 0)
    dedup = []
    for _ in range(count):
        length, pos = read_vlq(data, pos)
        dedup.append(data[pos : pos + length])
        pos += length
    blobs = []
    while pos < len(data):
        value, pos = read_vlq(data, pos)
        if value & 1:
            blobs.append(dedup[value >> 1])
        else:
            length = value >> 1
            blobs.append(data[pos : pos + length])
            pos += length
    return blobs


def blobby_records(path, width):
    with open(path, "rb") as f:
        blobs = decode_blobby(f.read())
    if len(blobs) % width:
        fatal(f"{path}: {len(blobs)} blobs is not a multiple of {width}")
    return [blobs[i : i + width] for i in range(0, len(blobs), width)]


def hx(data):
    return data.hex()


def build_cmac(openssl_mac, registry):
    out = []
    base = os.path.join(registry, "cmac-0.7.2", "tests", "data")
    for bits in (128, 192, 256):
        for n, (key, msg, tag) in enumerate(blobby_records(os.path.join(base, f"aes{bits}.blb"), 3), 1):
            out.append({
                "id": f"sp800-38b-aes{bits}-ex{n}",
                "source": f"NIST SP 800-38B Appendix D (via RustCrypto cmac 0.7.2 tests/data/aes{bits}.blb)",
                "key": hx(key), "msg": hx(msg), "tag": hx(tag), "valid": True,
            })
    for bits in (128, 192, 256):
        for n, (key, msg, tag) in enumerate(blobby_records(os.path.join(base, f"cavp_aes{bits}.blb"), 3), 1):
            out.append({
                "id": f"cavp-cmac-aes{bits}-{n}",
                "source": f"NIST CAVP CMACGenAES (via RustCrypto cmac 0.7.2 tests/data/cavp_aes{bits}.blb)",
                "key": hx(key), "msg": hx(msg), "tag": hx(tag), "valid": True,
            })
    for bits in (128, 192, 256):
        for n, (key, msg, tag) in enumerate(blobby_records(os.path.join(base, f"wycheproof-aes{bits}.blb"), 3), 1):
            out.append({
                "id": f"wycheproof-cmac-aes{bits}-{n}",
                "source": "Wycheproof aes_cmac_test (via RustCrypto cmac 0.7.2)",
                "key": hx(key), "msg": hx(msg), "tag": hx(tag), "valid": True,
            })
    n = 0
    for s in openssl_mac:
        if (s.get("MAC") in ("CMAC", "CMAC by EVP_PKEY")
                and s.get("Algorithm") in ("AES-128-CBC", "AES-192-CBC", "AES-256-CBC")
                and "Result" not in s):
            n += 1
            out.append({
                "id": f"openssl-cmac-{n}",
                "source": f"OpenSSL 3.1.2 test/recipes/30-test_evp_data/{OPENSSL_MAC} (CMAC tests from FIPS module)",
                "key": s["Key"].lower(), "msg": s.get("Input", "").lower(), "tag": s["Output"].lower(), "valid": True,
            })
    return out


def build_gcm(openssl_cipher, registry):
    out = []
    n = 0
    for s in openssl_cipher:
        if (s.get("Cipher", "").lower() in ("aes-128-gcm", "aes-192-gcm", "aes-256-gcm")
                and set(s) <= GCM_KEYS
                and len(s.get("IV", "")) == 24 and len(s.get("Tag", "")) == 32):
            n += 1
            out.append({
                "id": f"openssl-gcm-{n}",
                "source": f"OpenSSL 3.1.2 test/recipes/30-test_evp_data/{OPENSSL_CIPHER} (gcm-spec / NIST)",
                "key": s["Key"].lower(), "iv": s["IV"].lower(), "aad": s.get("AAD", "").lower(),
                "pt": s.get("Plaintext", "").lower(), "ct": s.get("Ciphertext", "").lower(),
                "tag": s["Tag"].lower(), "valid": "Result" not in s,
            })
    gcm = os.path.join(registry, "aes-gcm-0.10.3", "tests")
    block_re = re.compile(r"TestVector\s*\{(.*?)\}", re.DOTALL)
    field_re = re.compile(r'(\w+):\s*(?:&hex!\("([0-9a-fA-F]*)"\)|b"")')
    wanted = {"key", "nonce", "plaintext", "aad", "ciphertext", "tag"}
    for bits in (128, 256):
        path = os.path.join(gcm, f"aes{bits}gcm.rs")
        with open(path) as f:
            text = f.read()
        n = 0
        for block in block_re.findall(text):
            fields = {m.group(1): (m.group(2) or "").lower() for m in field_re.finditer(block)}
            if set(fields) != wanted:
                fatal(f"{path}: unexpected TestVector fields {sorted(fields)}")
            n += 1
            out.append({
                "id": f"cavp-gcm{bits}-{n}",
                "source": f"NIST CAVP gcmEncryptExtIV{bits}.rsp (via RustCrypto aes-gcm 0.10.3 tests/aes{bits}gcm.rs)",
                "key": fields["key"], "iv": fields["nonce"], "aad": fields["aad"],
                "pt": fields["plaintext"], "ct": fields["ciphertext"], "tag": fields["tag"], "valid": True,
            })
    for bits in (128, 256):
        n = 0
        path = os.path.join(gcm, "data", f"wycheproof-{bits}.blb")
        for key, nonce, aad, pt, ct_tag, status in blobby_records(path, 6):
            if len(ct_tag) < 16:
                continue
            n += 1
            out.append({
                "id": f"wycheproof-gcm{bits}-{n}",
                "source": "Wycheproof aes_gcm_test (via RustCrypto aes-gcm 0.10.3)",
                "key": hx(key), "iv": hx(nonce), "aad": hx(aad), "pt": hx(pt),
                "ct": hx(ct_tag[:-16]), "tag": hx(ct_tag[-16:]), "valid": status[0] == 1,
            })
    return [v for v in out if len(v["iv"]) == 24]


def build_gmac(openssl_mac, gcm):
    out = []
    n = 0
    for s in openssl_mac:
        if s.get("MAC") == "GMAC" and s.get("Algorithm", "").endswith("-GCM") and "Result" not in s:
            n += 1
            out.append({
                "id": f"openssl-gmac-{n}",
                "source": f"OpenSSL 3.1.2 test/recipes/30-test_evp_data/{OPENSSL_MAC} (GMAC: NIST, IEEE 802.1AE)",
                "key": s["Key"].lower(), "iv": s["IV"].lower(), "msg": s.get("Input", "").lower(),
                "tag": s["Output"].lower(), "valid": True,
            })
    for v in gcm:
        if not v["pt"] and not v["ct"]:
            out.append({
                "id": f"{v['id']}-gmac",
                "source": f"{v['source']}, empty plaintext = GMAC (SP 800-38D 3)",
                "key": v["key"], "iv": v["iv"], "msg": v["aad"], "tag": v["tag"], "valid": v["valid"],
            })
    return out


def build_shake(openssl_md):
    out = []
    n = 0
    for s in openssl_md:
        if s.get("Digest") == "SHAKE256" and set(s) == {"Digest", "Input", "Output"}:
            n += 1
            out.append({
                "id": f"openssl-shake256-{n}",
                "source": f"OpenSSL 3.1.2 test/recipes/30-test_evp_data/{OPENSSL_MD} (FIPS 202)",
                "msg": s["Input"].lower(), "out": s["Output"].lower(),
            })
    return out


def main():
    repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    cargo_home = os.environ.get("CARGO_HOME") or os.path.expanduser("~/.cargo")
    registries = sorted(glob.glob(os.path.join(cargo_home, "registry", "src", "index.crates.io-*")))
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--openssl-tarball", default=os.path.join(repo, "resources", "tarballs", "openssl-3.1.2.tar.gz"))
    parser.add_argument("--cargo-registry", default=registries[0] if len(registries) == 1 else None)
    parser.add_argument("--out", default=os.path.join(repo, "test_data", "kat_sources"))
    args = parser.parse_args()

    if not os.path.isfile(args.openssl_tarball):
        fatal(f"OpenSSL tarball not found: {args.openssl_tarball}")
    with open(args.openssl_tarball, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    if digest != OPENSSL_SHA256:
        fatal(f"unexpected OpenSSL tarball SHA-256 {digest}")
    if not args.cargo_registry:
        fatal("cannot find a single cargo registry; pass --cargo-registry")
    for crate in ("cmac-0.7.2", "aes-gcm-0.10.3"):
        if not os.path.isdir(os.path.join(args.cargo_registry, crate)):
            fatal(f'{crate} missing under {args.cargo_registry}: run "cargo fetch" first')

    with tarfile.open(args.openssl_tarball) as tar:
        def stanzas(name):
            member = tar.extractfile(OPENSSL_DATA + name)
            if member is None:
                fatal(f"{name} not found in the OpenSSL tarball")
            return parse_openssl_stanzas(member.read().decode())

        openssl_mac = stanzas(OPENSSL_MAC)
        openssl_cipher = stanzas(OPENSSL_CIPHER)
        openssl_md = stanzas(OPENSSL_MD)

    gcm = build_gcm(openssl_cipher, args.cargo_registry)
    files = {
        "aes_cmac.json": build_cmac(openssl_mac, args.cargo_registry),
        "aes_gcm.json": gcm,
        "aes_gmac.json": build_gmac(openssl_mac, gcm),
        "shake256.json": build_shake(openssl_md),
    }
    os.makedirs(args.out, exist_ok=True)
    for name, records in files.items():
        if not records:
            fatal(f"{name}: no vector produced")
        with open(os.path.join(args.out, name), "w") as f:
            json.dump(records, f, indent=1)
            f.write("\n")
        print(f"{name}: {len(records)} vectors")


if __name__ == "__main__":
    main()
