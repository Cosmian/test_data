#!/usr/bin/env python3
"""Convert official known-answer test vectors into JSON files for the KMS tests.

Sources:
  - the OpenSSL 3.1.2 tarball in resources/tarballs (the FIPS provider the KMS ships),
  - the RustCrypto `cmac` 0.7.2 and `aes-gcm` 0.10.3 crates in the cargo registry
    (NIST CAVP and Wycheproof data),
  - NIST ACVP-Server, C2SP Wycheproof and the NIST CAVP RSA zip, downloaded at pinned
    commits and verified against the SHA-256 in PINS (cached in --cache-dir).

Output (default: test_data/vectors/kat/sources): one JSON file per primitive, listed in main().
Every record carries its `source`. Reruns are byte-identical. Standard library only.
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import urllib.request
import zipfile

OPENSSL_SHA256 = "a0ce69b8b97ea6a35b96875235aa453b966ba3cba8af2de23657d8b6767d6539"
OPENSSL_DATA = "openssl-3.1.2/test/recipes/30-test_evp_data/"
OPENSSL_MAC = "evpmac_common.txt"
OPENSSL_CIPHER = "evpciph_aes_common.txt"
OPENSSL_MD = "evpmd_sha.txt"
GCM_KEYS = {"Cipher", "Key", "IV", "AAD", "Tag", "Plaintext", "Ciphertext", "NextIV", "Operation", "Result"}
OPENSSL_CHACHA = "evpciph_chacha.txt"
OPENSSL_WRAP = "evpciph_aes_wrap.txt"
OPENSSL_HKDF = "evpkdf_hkdf.txt"
OPENSSL_PBKDF2 = "evpkdf_pbkdf2.txt"

ACVP_COMMIT = "975de31eb83d87039ec88934fdc47d8c312b892d"
WYCHEPROOF_COMMIT = "65ca494727a52944c204441c860b039e6786b99b"
ACVP_URL = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/{commit}/gen-val/json-files/{name}/internalProjection.json"
WYCHEPROOF_URL = "https://raw.githubusercontent.com/C2SP/wycheproof/{commit}/testvectors_v1/{name}"
CAVP_RSA_URL = "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-3rsatestvectors.zip"
MAX_OUTPUT_BYTES = 1_048_576

PINS: dict[str, str] = {
    "acvp/ACVP-AES-ECB-1.0": "a804bbe1b4efbb775ec5a365245739ffaedad50f43d91b07ede26733e0f3b256",
    "acvp/ACVP-AES-CBC-1.0": "b6d11e684b279a384f27f4f711319dc2542bbe55f568bd8f11d5567a1df4a1df",
    "acvp/ACVP-AES-XTS-2.0": "3278b3311259bf7b206d7e66ce4bbe2ef5f21953174a2d39b9bf805be85aa68c",
    "acvp/ACVP-AES-GCM-SIV-1.0": "a355e8dd185700f046a802511af5928fd9f04ffd792cab77ab60122a946036cd",
    "acvp/ACVP-AES-KW-1.0": "f3307d3245bd30ab284fb04df2f24802a3a89de437416bd429426669dc56ff89",
    "acvp/ACVP-AES-KWP-1.0": "804f4422bb86e7632bd4ffdf292bd845e8204404f7b3c9eef74f81354bdf68ba",
    "acvp/ACVP-AES-FF1-1.0": "63cd6642095fbb1ce7af3fa53d7d720d725a58fe331d35ced1540b5e433668ee",
    "acvp/HMAC-SHA-1-2.0": "6e96eb5f53065219c437a99fedec7299c916c76e170d6b74507dc5409ed9cd6b",
    "acvp/HMAC-SHA2-224-2.0": "d67857c153e8005418171e06a32e10c28432f76d70ab291eb4a60b3bb39c3b79",
    "acvp/HMAC-SHA2-256-2.0": "a9d0734b93aee71bc6f30b47daab782fd96b39688afe4fbddb009e99402ec989",
    "acvp/HMAC-SHA2-384-2.0": "0ffa9332b9430ae94cfac0f23b3843293903fa34a3ac9c11a8af2bfdf7276ed3",
    "acvp/HMAC-SHA2-512-2.0": "ea6e03f012d5237b95421b7d50c504f8ab010c4f7f18cd46fe61d8912d3442a0",
    "acvp/HMAC-SHA3-224-2.0": "c09afee59b84df114ae9e4ec75ea880ab52cfad24a0225c8f4809a904d188409",
    "acvp/HMAC-SHA3-256-2.0": "a13ad967cf3752a11d5cb9bcb3e8eb10ea808f7c9087b768e434ccc6bbed4c89",
    "acvp/HMAC-SHA3-384-2.0": "3d4746555e0b50e8ffad167f93d42460499dcb5590eae76d7d4fcfb73a77e71d",
    "acvp/HMAC-SHA3-512-2.0": "d80da2085d5f2fcaabf96282b9d20737af4184de1aa749efa93b262612f6fced",
    "acvp/PBKDF-1.0": "09d0742e01e1ddfa484eeb1cbae3d2061620ebd6dc85fdabdbb2679713a6269f",
    "acvp/SHA2-224-1.0": "288d0a4dbec49759c63462ca9e4bd82b794e27f50605c8fca7fad0a415649ca9",
    "acvp/SHA2-256-1.0": "a7e0bf4f5c661f1787b343bf3ae1a809b1e62f8fb2c8a627791510d03a570a6c",
    "acvp/SHA2-384-1.0": "b22d80da99444af78feecaaae49493ee6189f1e6675e49db8764fb77bf16e847",
    "acvp/SHA2-512-1.0": "2b514c517a2ef150d240efc52fdb2c4127925f0b4291b5a5b9153515e0ec7478",
    "acvp/SHA3-224-2.0": "9ae4b1480d15526b29498d442125dfcfe80d74fe74c1b56fa840b1fae702ae34",
    "acvp/SHA3-256-2.0": "dba4689436c7e440e61dc517210def3e8e09e50c0e9eff29ea66d89bdd0f2c63",
    "acvp/SHA3-384-2.0": "e9eae46bd676dc82e911dcc3af92ef0093e0118615b62ab431086fce47574396",
    "acvp/SHA3-512-2.0": "b0521468a178f7fd362d63319aa69b708885d08f0c71cee99ac70729f5bdf64b",
    "acvp/ECDSA-SigVer-FIPS186-5": "45f9e9425e68b099d9c029e0e75ec04e9cc5943b60fa24cdb4d5af778f350b63",
    "acvp/DetECDSA-SigGen-FIPS186-5": "161813f3e67428d2ec656ef63a179efa95cf649d321fa7f7ae9333c8f57cc59e",
    "acvp/EDDSA-SigGen-1.0": "794d58fb39f08de4f852d63cb98b95c39bcc38ea42c7d42d09e92c15dadd5d81",
    "acvp/EDDSA-SigVer-1.0": "8556b9c48ef7ff209a9f866ed83e3c3881cfdd3c4c1ee1abe2602da69c1e97b0",
    "acvp/RSA-SigGen-FIPS186-5": "cce5b78db9c68a543c482a4c9a8f7336fcd1c625629322c81b7c8888ba67564b",
    "acvp/RSA-SigVer-FIPS186-5": "86088be5f46b3b10794357495c6d914af4a4c03b97bd3d185482f2d47d338578",
    "acvp/ML-KEM-keyGen-FIPS203": "d7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b",
    "acvp/ML-DSA-keyGen-FIPS204": "e67ee6540d40e11506c3c4e3b1f79fc1cefcd49820db99fc61f87cc8ba463baf",
    "acvp/ML-DSA-sigVer-FIPS204": "47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437",
    "acvp/SLH-DSA-sigGen-FIPS205": "62b42e7c27fda5de8a94aba2943ae413b59b6ea08141f3bc035b1eceae235dba",
    "acvp/SLH-DSA-sigVer-FIPS205": "a013fc2104f4ed4799d96d51141f65b965969b2cf10646626a021b6d456ce792",
    "cavp/186-3rsatestvectors.zip": "8405aeb3572a4f98ed4b1a3ccb3f2f49e725462dd28ec4759d6a15d88855d19c",
    "wycheproof/aes_cbc_pkcs5_test.json": "e45234427e10cf91f27324e52afe8c00906f294dbae061535e2ae13dd300a46a",
    "wycheproof/aes_gcm_siv_test.json": "d96e4f8c0db1a5e3b395907120f9d417d599507e7a08a1f60babff09ae276a8d",
    "wycheproof/aes_kwp_test.json": "e89624734deeba8bb937acba5381a5cb137c7050bf8bfd0bd70bd8438170b436",
    "wycheproof/aes_wrap_test.json": "2fdb3661fd8823d1ec50e03886b24066415018975677dff83d83e77f5a51562d",
    "wycheproof/chacha20_poly1305_test.json": "fe61d25f90e1bde4461d00eafe61049e5f29bd999f36b766df9cda90906ad53d",
    "wycheproof/hkdf_sha1_test.json": "f157dae1e46582db5d13d2e9133e4e3334f3151b2f95eff421f11aa7a548a930",
    "wycheproof/hkdf_sha256_test.json": "bb2b462a38b251cb52a2aede706d6d4b62b26864f4e80c95497507ddb07c5f1e",
    "wycheproof/hkdf_sha384_test.json": "69ff6ea3657bb9c1b8cdffbbb4e7832353d08fd15c0d9997b03f7a6b180e3678",
    "wycheproof/hkdf_sha512_test.json": "bb9a21f4e86041caf5d7792b030349f8ff289087f195b2fbc0fc0afc39deca6f",
    "wycheproof/hmac_sha1_test.json": "b521c6180a862247986392d3cb49b511fc7fe790e75bee236f84e36ca290c7c0",
    "wycheproof/hmac_sha224_test.json": "9b3a2470fe5bc8aa2d3e55f19772dc1f88fda897863ed4eaa4d8536c244c320b",
    "wycheproof/hmac_sha256_test.json": "2d201cfa61d1bf95e6f5d07d96634b4a348b31e8eaa277ad7c8d09677b7a743f",
    "wycheproof/hmac_sha384_test.json": "28b9776e979dd755d852ca471043ea6cedce8b15f7a28abdf6ea9efd982b43c0",
    "wycheproof/hmac_sha512_test.json": "b6c90477bdb4a6fc8ee3d1f7b2c0b69a8dfffab34718abaa6cabd71cc2ba1207",
    "wycheproof/hmac_sha3_224_test.json": "b795ca6ed71afb662b3b2f8258aa6bbab6056103235301391bba8c25bf4b64ca",
    "wycheproof/hmac_sha3_256_test.json": "8f1bad7c725c0f6325ea975ddd661f51663862823cd07084b230efe0f6a0ed6b",
    "wycheproof/hmac_sha3_384_test.json": "66423781ae4aa991b8b457b7736659604fffd46688001ca749f444da18f06728",
    "wycheproof/hmac_sha3_512_test.json": "60cd4c3be286a9c6ce49d93ce6901762e3cd0ebbfc4f08ccfd5f2b595c641860",
    "wycheproof/pbkdf2_hmacsha1_test.json": "5ef5307e119bd118da50ad276426ed3baade2d093e93b643a1d70be0bf0b861a",
    "wycheproof/pbkdf2_hmacsha224_test.json": "e6c835600fe798c5da9ee33cf4f17ca9ceff520d492529b2e190a2c774f2fe9b",
    "wycheproof/pbkdf2_hmacsha256_test.json": "1bf37af2cefe40c829ee9ecebb3505bb6424be8824bc97aa3e1c2076e860d192",
    "wycheproof/pbkdf2_hmacsha384_test.json": "892613e78d38f1b81df77f1321a59a9fbf6d5c5d1c702126b9f709d7fd242483",
    "wycheproof/pbkdf2_hmacsha512_test.json": "6a764a448b7a283478340d58f5dc20455524e8589a935fb0d66fb851e997b1c8",
    "wycheproof/ecdsa_secp256r1_sha256_test.json": "182db4f3e230f6f9fa9f800d2a614dede30284b8e8438bbfe1171905402e9332",
    "wycheproof/ecdsa_secp384r1_sha384_test.json": "8a5b3ae1760975143414811f13588c24d951d9d8c904195087ba327591dfe9cc",
    "wycheproof/ecdsa_secp521r1_sha512_test.json": "0fa3bb09a2319242253028b53d555fb8ec2081d891271321205cdaeabb3eef3e",
    "wycheproof/ecdsa_secp256k1_sha256_test.json": "43db761c0a2eae71fb0755d355d5130e28ce64a5b07846cf27e7072082597a81",
    "wycheproof/ed25519_test.json": "ea80ffebac085e21cb9d3e903e7fa2b448d96702da5b31f061d0b83b430b74b3",
    "wycheproof/ed448_test.json": "3b3c7995853deb2fbbb49fba0fd292f314dc081f9154bd33252f294ca211289a",
    "wycheproof/x25519_test.json": "35c3f5231cf25cc640b524d403461deee9e49441d5d915a3a25b2c8ff5adbe7d",
    "wycheproof/ecdh_secp256r1_ecpoint_test.json": "648f16d077caf2400d02331ca51f44744c72c799830c8d0595d0b18b6dd9f886",
    "wycheproof/ecdh_secp384r1_ecpoint_test.json": "ffa7835fe1de359dff762c8f1272b98acebd5578e2f855d969051ff956c6dca3",
    "wycheproof/ecdh_secp521r1_ecpoint_test.json": "87aba8739c96de2bde8c75b60ffea09d0493192c4d9543d1d969e5e998931f35",
    "wycheproof/rsa_oaep_2048_sha256_mgf1sha256_test.json": "83dce701e3d8640ac56e6d7bf37a5a8f9bd6a336e1e932a1e9bfe4ba9c5ea3a9",
    "wycheproof/rsa_oaep_2048_sha256_mgf1sha1_test.json": "d3f25242297957b3663ab5c9a7ff3fe7e34f8171ed1ff275842a0cfaccb5104d",
    "wycheproof/rsa_oaep_2048_sha384_mgf1sha384_test.json": "b789151c90035789b5760f3c3bc3cb2338604b482362a31b22a0fdedce73b21c",
    "wycheproof/rsa_oaep_2048_sha512_mgf1sha512_test.json": "37aa37a21910b59fcca10c29ffc726ff2f437938455457314d30587c1ebeee86",
    "wycheproof/rsa_oaep_3072_sha256_mgf1sha256_test.json": "c8122302f522bfd539650c71c4aa966bd1f89acb50c6f4c190030fdb9b2684a4",
    "wycheproof/rsa_oaep_4096_sha256_mgf1sha256_test.json": "e0eb85bcd6d66a85941ee3d98e44f7d1ffb0cf870ba6550e1ed3bec4174c60a9",
    "wycheproof/rsa_oaep_4096_sha512_mgf1sha512_test.json": "5b5a83d2071b8aeb4aa8463adb8150bb0422ee1c461e4ab33f7e3dd63c79c0d6",
    "wycheproof/rsa_pkcs1_2048_test.json": "28466c4390f1f8943754a990ba36397ebbac628117d91b57f87e1ba200b932f3",
    "wycheproof/rsa_pkcs1_3072_test.json": "c85a9f9d431789e1b9243bdc7d71bf0160ee5a5b40be2e1ada892b98e21eb4ab",
    "wycheproof/rsa_pkcs1_4096_test.json": "80046c2964ff551e054cdd5bb7c1d2c3758b1a0225b1a5b3bd6ace8ee0a7219b",
    "wycheproof/rsa_signature_2048_sha256_test.json": "94a917b01ff50fb874cfc05bf29b4af44868d944a6558201cf18380da93fb393",
    "wycheproof/rsa_signature_2048_sha384_test.json": "c571c105d261c0ff588a2888a529f152563fb3b77894b7620d4e4f8f934f2c1d",
    "wycheproof/rsa_signature_2048_sha512_test.json": "16ea24b039905d054bdb6004f5fd179374e150b7b6d73a7ba654b6d00eab12ef",
    "wycheproof/rsa_signature_3072_sha256_test.json": "0f5f18cabfaad3e2792e82f7e9882f8999049b456714de924b8a5e202f61ca43",
    "wycheproof/rsa_signature_3072_sha384_test.json": "73499ee649d8fb703b3f0f455fa36f7682fde677c590a736958ebce05ab27dae",
    "wycheproof/rsa_signature_3072_sha512_test.json": "09aa3336fdb7be216180ce944ca7b2a052e1de38c210435c19506327d4a36ebd",
    "wycheproof/rsa_signature_4096_sha256_test.json": "957aca128e30bd02c8982f8ca482d6521d16683f4bbc3f193cdfd4c8f04bc667",
    "wycheproof/rsa_signature_4096_sha384_test.json": "bc26f16b9fc9a90628864d3d1111ef48a4bd00b9d4870bfab88ff326e309e073",
    "wycheproof/rsa_signature_4096_sha512_test.json": "9d6e67b1eb0d7040db411835238efd20e9302399a258bdff82de3f38e0f2855a",
    "wycheproof/rsa_signature_2048_sha3_256_test.json": "1f9598c12de63d235788a46f518ccc6c7f7e76329d17e2d6813a86dd126b16f8",
    "wycheproof/rsa_signature_3072_sha3_384_test.json": "508c37189e9d6204a0d457f5e6d612093207b1e9f5f49dd3858d5b8488c7bccd",
    "wycheproof/rsa_pss_2048_sha256_mgf1_32_test.json": "7f6efafc160f4816b96cbf1c12188a31051d7e3f001e27505d9edb5f2a0e325c",
    "wycheproof/rsa_pss_3072_sha256_mgf1_32_test.json": "cca48433e6d1accb57f65b3396c4f4dd93c776467101c3f0948e74c283fd4749",
    "wycheproof/rsa_pss_4096_sha256_mgf1_32_test.json": "e627cbf5139a01e0a446c4fe15911f6268224fdd3ef4a1eb714b3942b5686410",
    "wycheproof/rsa_pss_2048_sha384_mgf1_48_test.json": "66d464778b0b2f683a1d1a20e94f77e9472b8cc393b45f423fa08a48e677063c",
    "wycheproof/rsa_pss_4096_sha384_mgf1_48_test.json": "d632649a7630f7c267eda576714ca11cf0ff068d6622f576b8701f923c112577",
    "wycheproof/rsa_pss_4096_sha512_mgf1_64_test.json": "c93ceaa56a190c9fd4707441c5c6a75839f108202d88aec891697f9623042547",
    "wycheproof/mlkem_512_test.json": "18bc5455d5bf8226b3ab1d1deb51f3ed7c44b3d90039eb25416d40fa77e76f20",
    "wycheproof/mlkem_768_test.json": "c59c067ae794c343df575dd90f6f7458f51881b11a22d6e9d8677c8d9ee21e90",
    "wycheproof/mlkem_1024_test.json": "17c5b764d78c05522f1980fcb41d82add573f11de5d13004ae0b83bf46d9c43a",
    "wycheproof/mldsa_44_verify_test.json": "f70759c95146ff3057ae9708438f6e8d25ba822e3af11d2e87bb20d9a9c39d0e",
    "wycheproof/mldsa_65_verify_test.json": "1ca235f61928421a173a171780beb00264ae9155dc33c52a11e1766cc7979034",
    "wycheproof/mldsa_87_verify_test.json": "54adffe10f6dad7941ffd97f77ad4e5c85cb3a54d44cf5ce1c95cb1757b9ba14",
}


def fatal(message):
    print(f"ERROR: {message}", file=sys.stderr)
    sys.exit(1)


CACHE_DIR = ""


def fetch(key: str, url: str, cache_dir: str) -> bytes:
    """Return the pinned file, from the cache or downloaded once. A cached file that no longer
    matches its pin is an error (delete it to re-download)."""
    want = PINS[key]
    path = os.path.join(cache_dir, key)
    if os.path.isfile(path):
        with open(path, "rb") as f:
            data = f.read()
        got = hashlib.sha256(data).hexdigest()
        if got != want:
            fatal(f"{key}: SHA-256 {got} != pinned {want} (cached {path})")
        return data
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 kat-importer"})  # csrc.nist.gov rejects the default agent
        with urllib.request.urlopen(request, timeout=120) as response:
            data = response.read()
    except OSError as e:
        fatal(f"{key}: cannot download {url}: {e}")
    got = hashlib.sha256(data).hexdigest()
    if got != want:
        fatal(f"{key}: SHA-256 {got} != pinned {want}")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    return data


def acvp(name: str) -> dict:
    """Parsed ACVP-Server internalProjection.json."""
    url = ACVP_URL.format(commit=ACVP_COMMIT, name=name)
    return json.loads(fetch(f"acvp/{name}", url, CACHE_DIR))


def wycheproof(file: str) -> dict:
    """Parsed Wycheproof testvectors_v1 file."""
    url = WYCHEPROOF_URL.format(commit=WYCHEPROOF_COMMIT, name=file)
    return json.loads(fetch(f"wycheproof/{file}", url, CACHE_DIR))


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


HASH_NAMES: dict[str, str] = {}
for _canonical, _spellings in {
    "SHA-1": ("SHA-1", "SHA1", "sha1"),
    "SHA-224": ("SHA-224", "SHA2-224", "SHA224"),
    "SHA-256": ("SHA-256", "SHA2-256", "SHA256", "sha256"),
    "SHA-384": ("SHA-384", "SHA2-384", "SHA384"),
    "SHA-512": ("SHA-512", "SHA2-512", "SHA512", "sha512"),
    "SHA3-224": ("SHA3-224", "sha3-224"),
    "SHA3-256": ("SHA3-256", "sha3-256"),
    "SHA3-384": ("SHA3-384", "sha3-384"),
    "SHA3-512": ("SHA3-512", "sha3-512"),
}.items():
    for _spelling in _spellings:
        HASH_NAMES[_spelling] = _canonical
DIGEST_BYTES = {"SHA-1": 20, "SHA-224": 28, "SHA-256": 32, "SHA-384": 48, "SHA-512": 64,
                "SHA3-224": 28, "SHA3-256": 32, "SHA3-384": 48, "SHA3-512": 64}
# KDFs in the KMS go through get_md / get_message_digest, which reject SHA-3.
KDF_HASHES = {h for h in DIGEST_BYTES if not h.startswith("SHA3")}

WYCHEPROOF_HASH_FILES = {"sha1": "SHA-1", "sha224": "SHA-224", "sha256": "SHA-256", "sha384": "SHA-384",
                         "sha512": "SHA-512", "sha3_224": "SHA3-224", "sha3_256": "SHA3-256",
                         "sha3_384": "SHA3-384", "sha3_512": "SHA3-512"}
CURVES = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521", "secp256k1": "secp256k1",
          "P-256": "P-256", "P-384": "P-384", "P-521": "P-521"}
FIELD_BYTES = {"P-256": 32, "P-384": 48, "P-521": 66}
ML_DSA_OIDS = {"ML-DSA-44": "2.16.840.1.101.3.4.3.17", "ML-DSA-65": "2.16.840.1.101.3.4.3.18",
               "ML-DSA-87": "2.16.840.1.101.3.4.3.19"}
SLH_DSA_OIDS = {f"SLH-DSA-{family}-{level}{variant}": f"2.16.840.1.101.3.4.3.{20 + i}"
                for i, (family, level, variant) in enumerate(
                    (f, l, v) for f in ("SHA2", "SHAKE") for l in ("128", "192", "256") for v in ("s", "f"))}


def acvp_source(name: str) -> str:
    return f"NIST ACVP-Server {ACVP_COMMIT[:7]} gen-val/json-files/{name}"


def wycheproof_source(file: str) -> str:
    return f"Wycheproof {WYCHEPROOF_COMMIT[:7]} testvectors_v1/{file}"


def openssl_source(file: str) -> str:
    return f"OpenSSL 3.1.2 test/recipes/30-test_evp_data/{file}"


def wycheproof_records(doc: dict):
    """(group, test, valid) for every non-"acceptable" Wycheproof test."""
    for group in doc["testGroups"]:
        for test in group["tests"]:
            if test["result"] != "acceptable":
                yield group, test, test["result"] == "valid"


def acvp_aft_groups(name: str):
    """AFT groups of an ACVP file; files without testType are all AFT."""
    for group in acvp(name)["testGroups"]:
        if group.get("testType", "AFT") == "AFT":
            yield group


def acvp_id(name: str, group: dict, test: dict) -> str:
    return f"acvp-{name.lower()}-tg{group['tgId']}-tc{test['tcId']}"


def passed(test: dict) -> bool:
    return test.get("testPassed", True)


def openssl_hex(value: str) -> str:
    """OpenSSL test data is hex, or a double-quoted ASCII literal."""
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1].encode().hex()
    return value.lower()


def trim(hex_value: str, bits: int) -> str:
    """Lower-case hex cut to `bits` bits (ACVP pads short values)."""
    return hex_value.lower()[: bits // 4]


def norm_hex_int(hex_value: str) -> str:
    """Even-length lower-case hex of an unsigned integer without leading zero bytes."""
    value = hex_value.lower().lstrip("0") or "0"
    return value.zfill(len(value) + len(value) % 2)


def der_len(n: int) -> bytes:
    if n < 128:
        return bytes([n])
    return b"\x81" + bytes([n]) if n < 256 else b"\x82" + n.to_bytes(2, "big")


def der_uint(hex_value: str) -> bytes:
    raw = bytes.fromhex(hex_value.zfill(len(hex_value) + len(hex_value) % 2)).lstrip(b"\x00") or b"\x00"
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return b"\x02" + der_len(len(raw)) + raw


def der_ecdsa_sig(r_hex: str, s_hex: str) -> str:
    body = der_uint(r_hex) + der_uint(s_hex)
    return (b"\x30" + der_len(len(body)) + body).hex()


def der_oid(dotted: str) -> bytes:
    arcs = [int(a) for a in dotted.split(".")]
    body = bytes([40 * arcs[0] + arcs[1]])
    for arc in arcs[2:]:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7F))
            arc >>= 7
        body += bytes(reversed(chunk))
    return b"\x06" + der_len(len(body)) + body


def spki(oid: str, raw_hex: str) -> str:
    """SubjectPublicKeyInfo for a PQC public key with no algorithm parameters."""
    algorithm = b"\x30" + der_len(len(der_oid(oid))) + der_oid(oid)
    bits = b"\x03" + der_len(len(raw_hex) // 2 + 1) + b"\x00" + bytes.fromhex(raw_hex)
    body = algorithm + bits
    return (b"\x30" + der_len(len(body)) + body).hex()


def cipher_vector(vid: str, source: str, key: str, iv: str, pt: str, ct: str, valid: bool = True) -> dict:
    return {"id": vid, "source": source, "key": key.lower(), "iv": iv.lower(), "pt": pt.lower(), "ct": ct.lower(),
            "valid": valid}


def build_aes_ecb_cbc(name: str) -> list[dict]:
    out = []
    for group in acvp_aft_groups(name):
        for t in group["tests"][:16]:
            out.append(cipher_vector(acvp_id(name, group, t), acvp_source(name), t["key"], t.get("iv", ""),
                                     t["pt"], t["ct"], passed(t)))
    return out


def build_aes_cbc_pkcs5() -> list[dict]:
    file = "aes_cbc_pkcs5_test.json"
    return [cipher_vector(f"wycheproof-aes_cbc_pkcs5-{t['tcId']}", wycheproof_source(file), t["key"], t["iv"],
                          t["msg"], t["ct"], valid)
            for _, t, valid in wycheproof_records(wycheproof(file))]


def build_aes_xts() -> list[dict]:
    name = "ACVP-AES-XTS-2.0"
    out = []
    for group in acvp_aft_groups(name):
        if group.get("tweakMode") != "hex":
            continue
        kept = [t for t in group["tests"]
                if int(t["payloadLen"]) % 8 == 0 and 128 <= int(t["payloadLen"]) <= 1024
                and int(t["dataUnitLen"]) == int(t["payloadLen"])]
        for t in kept[:8]:
            bits = int(t["payloadLen"])
            out.append(cipher_vector(acvp_id(name, group, t), acvp_source(name), t["key"], t["tweakValue"],
                                     trim(t["pt"], bits), trim(t["ct"], bits), passed(t)))
    return out


def build_chacha20(openssl_chacha: list[dict]) -> list[dict]:
    out = []
    for s in openssl_chacha:
        iv = s.get("IV", "")
        if (s.get("Cipher", "").lower() == "chacha20"
                and set(s) <= {"Cipher", "Key", "IV", "Plaintext", "Ciphertext"}
                and len(iv) == 32 and set(iv[:16]) == {"0"}):
            out.append(cipher_vector(f"openssl-chacha20-{len(out) + 1}", openssl_source(OPENSSL_CHACHA), s["Key"],
                                     iv[16:], s.get("Plaintext", ""), s.get("Ciphertext", "")))
    return out


def aead_vector(vid: str, source: str, key: str, iv: str, aad: str, pt: str, ct: str, tag: str, valid: bool) -> dict:
    return {"id": vid, "source": source, "key": key.lower(), "iv": iv.lower(), "aad": aad.lower(),
            "pt": pt.lower(), "ct": ct.lower(), "tag": tag.lower(), "valid": valid}


def wycheproof_aead(file: str, prefix: str) -> list[dict]:
    return [aead_vector(f"wycheproof-{prefix}-{t['tcId']}", wycheproof_source(file), t["key"], t["iv"], t["aad"],
                        t["msg"], t["ct"], t["tag"], valid)
            for g, t, valid in wycheproof_records(wycheproof(file))
            if int(g["ivSize"]) == 96 and int(g["tagSize"]) == 128]


def build_aes_gcm_siv() -> list[dict]:
    name = "ACVP-AES-GCM-SIV-1.0"
    out = []
    for group in acvp_aft_groups(name):
        for t in group["tests"]:
            ct_tag = t["ct"]
            out.append(aead_vector(acvp_id(name, group, t), acvp_source(name), t["key"], t["iv"], t.get("aad", ""),
                                   t.get("pt", ""), ct_tag[:-32], ct_tag[-32:], passed(t)))
    return out + wycheproof_aead("aes_gcm_siv_test.json", "aes_gcm_siv")


def build_chacha20_poly1305(openssl_chacha: list[dict]) -> list[dict]:
    out = wycheproof_aead("chacha20_poly1305_test.json", "chacha20_poly1305")
    for s in openssl_chacha:
        if (s.get("Cipher", "").lower() == "chacha20-poly1305" and set(s) <= GCM_KEYS
                and len(s.get("IV", "")) == 24 and len(s.get("Tag", "")) == 32):
            out.append(aead_vector(f"openssl-chacha20_poly1305-{len(out) + 1}", openssl_source(OPENSSL_CHACHA),
                                   s["Key"], s["IV"], s.get("AAD", ""), s.get("Plaintext", ""),
                                   s.get("Ciphertext", ""), s["Tag"], "Result" not in s))
    return out


def wrap_vector(vid: str, source: str, key: str, pt: str, ct: str, valid: bool) -> dict:
    return {"id": vid, "source": source, "key": key.lower(), "pt": pt.lower(), "ct": ct.lower(), "valid": valid}


def build_wrap(acvp_name: str, wycheproof_file: str, openssl_ciphers: set[str], openssl_wrap: list[dict],
               max_payload_bits: int, per_group: int) -> list[dict]:
    out = []
    for group in acvp_aft_groups(acvp_name):
        if group["kwCipher"] != "cipher" or int(group["payloadLen"]) > max_payload_bits:
            continue
        for t in group["tests"][:per_group]:
            out.append(wrap_vector(acvp_id(acvp_name, group, t), acvp_source(acvp_name), t["key"], t.get("pt", ""),
                                   t["ct"], passed(t)))
    stem = wycheproof_file.removesuffix("_test.json")
    for _, t, valid in wycheproof_records(wycheproof(wycheproof_file)):
        out.append(wrap_vector(f"wycheproof-{stem}-{t['tcId']}", wycheproof_source(wycheproof_file), t["key"],
                               t["msg"], t["ct"], valid))
    n = 0
    for s in openssl_wrap:
        if s.get("Cipher", "").lower() in openssl_ciphers and set(s) <= {"Cipher", "Key", "Plaintext", "Ciphertext"}:
            n += 1
            out.append(wrap_vector(f"openssl-{stem}-{n}", openssl_source(OPENSSL_WRAP), s["Key"],
                                   s.get("Plaintext", ""), s.get("Ciphertext", ""), True))
    return out


def build_aes_ff1() -> list[dict]:
    name = "ACVP-AES-FF1-1.0"
    out = []
    for group in acvp_aft_groups(name):
        if int(group["keyLen"]) != 256:
            continue
        index = {c: i for i, c in enumerate(group["alphabet"])}
        for t in group["tests"][:10]:
            if group["radix"] ** len(t["pt"]) < 1_000_000:
                continue
            out.append({"id": acvp_id(name, group, t), "source": acvp_source(name), "key": t["key"].lower(),
                        "radix": group["radix"], "tweak": t["tweak"].lower(),
                        "pt": [index[c] for c in t["pt"]], "ct": [index[c] for c in t["ct"]]})
    return out


def build_hmac(openssl_mac: list[dict]) -> list[dict]:
    out = []
    for name in ["HMAC-SHA-1-2.0"] + [f"HMAC-SHA2-{n}-2.0" for n in (224, 256, 384, 512)] \
            + [f"HMAC-SHA3-{n}-2.0" for n in (224, 256, 384, 512)]:
        digest = name.removeprefix("HMAC-").removesuffix("-2.0")
        hash_name = HASH_NAMES[digest.replace("SHA-1", "SHA1")]
        kept = 0
        for group in acvp_aft_groups(name):
            for t in group["tests"]:
                key_bits, msg_bits = int(t["keyLen"]), int(t["msgLen"])
                if key_bits % 8 or msg_bits % 8 or kept >= 20:
                    continue
                kept += 1
                out.append({"id": acvp_id(name, group, t), "source": acvp_source(name), "hash": hash_name,
                            "key": trim(t["key"], key_bits), "msg": trim(t["msg"], msg_bits),
                            "tag": t["mac"].lower(), "valid": True})
    for suffix, hash_name in WYCHEPROOF_HASH_FILES.items():
        file = f"hmac_{suffix}_test.json"
        for _, t, valid in list(wycheproof_records(wycheproof(file)))[:60]:
            out.append({"id": f"wycheproof-hmac_{suffix}-{t['tcId']}", "source": wycheproof_source(file),
                        "hash": hash_name, "key": t["key"], "msg": t["msg"], "tag": t["tag"], "valid": valid})
    n = 0
    for s in openssl_mac:
        if (s.get("MAC") == "HMAC" and set(s) <= {"MAC", "Algorithm", "Key", "Input", "Output"}
                and s.get("Algorithm") in HASH_NAMES):
            n += 1
            out.append({"id": f"openssl-hmac-{n}", "source": openssl_source(OPENSSL_MAC),
                        "hash": HASH_NAMES[s["Algorithm"]], "key": openssl_hex(s["Key"]),
                        "msg": openssl_hex(s.get("Input", "")), "tag": s["Output"].lower(), "valid": True})
    return out


def ctrl_text(stanza: dict, field: str, text_prefix: str, hex_prefix: str) -> str | None:
    """UTF-8 or hex OpenSSL control value, returned as hex; None if absent."""
    value = stanza.get(f"Ctrl.{field}")
    if value is None:
        return None
    if value.startswith(hex_prefix):
        return value[len(hex_prefix):].lower()
    if value.startswith(text_prefix):
        return value[len(text_prefix):].encode().hex()
    return None


def build_hkdf(openssl_hkdf: list[dict]) -> list[dict]:
    out = []
    for suffix in ("sha1", "sha256", "sha384", "sha512"):
        file = f"hkdf_{suffix}_test.json"
        for _, t, valid in wycheproof_records(wycheproof(file)):
            out.append({"id": f"wycheproof-hkdf_{suffix}-{t['tcId']}", "source": wycheproof_source(file),
                        "hash": WYCHEPROOF_HASH_FILES[suffix], "ikm": t["ikm"], "salt": t["salt"], "info": t["info"],
                        "size": int(t["size"]), "okm": t.get("okm", ""), "valid": valid})
    n = 0
    for s in openssl_hkdf:
        digest = s.get("Ctrl.digest", "").removeprefix("digest:")
        ikm = s.get("Ctrl.IKM", "")
        if (s.get("KDF") == "HKDF" and "Ctrl.mode" not in s and HASH_NAMES.get(digest) in KDF_HASHES
                and ikm.startswith("hexkey:") and "Output" in s):
            n += 1
            out.append({"id": f"openssl-hkdf-{n}", "source": openssl_source(OPENSSL_HKDF),
                        "hash": HASH_NAMES[digest], "ikm": ikm.removeprefix("hexkey:").lower(),
                        "salt": ctrl_text(s, "salt", "salt:", "hexsalt:") or "",
                        "info": ctrl_text(s, "info", "info:", "hexinfo:") or "",
                        "size": len(s["Output"]) // 2, "okm": s["Output"].lower(), "valid": True})
    return out


def build_pbkdf2(openssl_pbkdf2: list[dict]) -> list[dict]:
    out = []
    name = "PBKDF-1.0"
    for group in acvp_aft_groups(name):
        hash_name = HASH_NAMES.get(group["hmacAlg"])
        if hash_name not in KDF_HASHES:
            continue
        for t in group["tests"]:
            if int(t["iterationCount"]) > 100000:
                continue
            out.append({"id": acvp_id(name, group, t), "source": acvp_source(name), "hash": hash_name,
                        "password": t["password"].encode().hex(), "salt": t["salt"].lower(),
                        "iterations": int(t["iterationCount"]), "dk": trim(t["derivedKey"], int(t["keyLen"])),
                        "valid": True})
    for suffix in ("sha1", "sha224", "sha256", "sha384", "sha512"):
        file = f"pbkdf2_hmac{suffix}_test.json"
        for _, t, valid in wycheproof_records(wycheproof(file)):
            if int(t["iterationCount"]) > 100000:
                continue
            out.append({"id": f"wycheproof-pbkdf2_hmac{suffix}-{t['tcId']}", "source": wycheproof_source(file),
                        "hash": WYCHEPROOF_HASH_FILES[suffix], "password": t["password"], "salt": t["salt"],
                        "iterations": int(t["iterationCount"]), "dk": t["dk"], "valid": valid})
    n = 0
    for s in openssl_pbkdf2:
        digest = s.get("Ctrl.digest", "").removeprefix("digest:")
        iterations = s.get("Ctrl.iter", "").removeprefix("iter:")
        password = ctrl_text(s, "pass", "pass:", "hexpass:") if "Ctrl.pass" in s else ctrl_text(s, "hexpass", "", "hexpass:")
        salt = ctrl_text(s, "salt", "salt:", "hexsalt:") if "Ctrl.salt" in s else ctrl_text(s, "hexsalt", "", "hexsalt:")
        if (s.get("KDF") == "PBKDF2" and "Result" not in s and HASH_NAMES.get(digest) in KDF_HASHES
                and iterations.isdigit() and int(iterations) <= 100000
                and password is not None and salt is not None and "Output" in s):
            n += 1
            out.append({"id": f"openssl-pbkdf2-{n}", "source": openssl_source(OPENSSL_PBKDF2),
                        "hash": HASH_NAMES[digest], "password": password, "salt": salt,
                        "iterations": int(iterations), "dk": s["Output"].lower(), "valid": True})
    return out


def build_sha(openssl_md: list[dict]) -> list[dict]:
    out = []
    for name in [f"SHA2-{n}-1.0" for n in (224, 256, 384, 512)] + [f"SHA3-{n}-2.0" for n in (224, 256, 384, 512)]:
        hash_name = HASH_NAMES[name.rsplit("-", 1)[0]]
        kept = 0
        for group in acvp_aft_groups(name):
            for t in group["tests"]:
                bits = int(t["len"])
                if bits % 8 or bits > 2048 or kept >= 32:
                    continue
                kept += 1
                out.append({"id": acvp_id(name, group, t), "source": acvp_source(name), "hash": hash_name,
                            "msg": trim(t["msg"], bits), "md": t["md"].lower()})
    n = 0
    for s in openssl_md:
        if set(s) == {"Digest", "Input", "Output"} and s["Digest"] in HASH_NAMES:
            n += 1
            out.append({"id": f"openssl-sha-{n}", "source": openssl_source(OPENSSL_MD),
                        "hash": HASH_NAMES[s["Digest"]], "msg": openssl_hex(s["Input"]), "md": s["Output"].lower()})
    return out


def sig_test(vid: str, msg: str, sig: str, valid: bool) -> dict:
    return {"id": vid, "msg": msg.lower(), "sig": sig.lower(), "valid": valid}


def build_ecdsa_verify(curves: tuple[str, ...]) -> list[dict]:
    """Wycheproof ECDSA verify groups for `curves`, plus ACVP when P-curves are requested."""
    out = []
    files = {"secp256r1": "ecdsa_secp256r1_sha256_test.json", "secp384r1": "ecdsa_secp384r1_sha384_test.json",
             "secp521r1": "ecdsa_secp521r1_sha512_test.json", "secp256k1": "ecdsa_secp256k1_sha256_test.json"}
    for curve in curves:
        file = files[curve]
        doc = wycheproof(file)
        for group in doc["testGroups"]:
            tests = [sig_test(f"wycheproof-{file.removesuffix('_test.json')}-{t['tcId']}", t["msg"], t["sig"], valid)
                     for t in group["tests"] if (valid := t["result"] == "valid") or t["result"] == "invalid"]
            if tests:
                out.append({"source": wycheproof_source(file), "curve": CURVES[curve],
                            "hash": HASH_NAMES[group["sha"]], "public": group["publicKey"]["uncompressed"],
                            "tests": tests})
    return out


def build_ecdsa_acvp_verify() -> list[dict]:
    name = "ECDSA-SigVer-FIPS186-5"
    out = []
    for group in acvp_aft_groups(name):
        curve = group["curve"]
        hash_name = HASH_NAMES.get(group["hashAlg"])
        if curve not in FIELD_BYTES or hash_name not in ("SHA-256", "SHA-384", "SHA-512"):
            continue
        width = FIELD_BYTES[curve] * 2
        for t in group["tests"]:
            out.append({"source": acvp_source(name), "curve": curve, "hash": hash_name,
                        "public": "04" + t["qx"].lower().zfill(width) + t["qy"].lower().zfill(width),
                        "tests": [sig_test(acvp_id(name, group, t), t["message"], der_ecdsa_sig(t["r"], t["s"]),
                                           passed(t))]})
    return out


def build_ecdsa_p256_sign() -> list[dict]:
    name = "DetECDSA-SigGen-FIPS186-5"
    out = []
    for group in acvp_aft_groups(name):
        # SP800-106 groups sign msg || randomValue, not the plain message
        if group["curve"] != "P-256" or group["hashAlg"] != "SHA2-256" or group.get("conformance"):
            continue
        for t in group["tests"][:10]:
            out.append({"id": acvp_id(name, group, t), "source": acvp_source(name), "curve": "P-256",
                        "hash": "SHA-256", "private": group["d"].lower().zfill(64), "msg": t["message"].lower(),
                        "sig": der_ecdsa_sig(t["r"], t["s"])})
    return out


def build_eddsa(curve_acvp: str, file: str) -> list[dict]:
    out = []
    for group in wycheproof(file)["testGroups"]:
        tests = [sig_test(f"wycheproof-{file.removesuffix('_test.json')}-{t['tcId']}", t["msg"], t["sig"], valid)
                 for t in group["tests"] if (valid := t["result"] == "valid") or t["result"] == "invalid"]
        if tests:
            out.append({"source": wycheproof_source(file), "private": "", "public": group["publicKey"]["pk"],
                        "tests": tests})
    gen = "EDDSA-SigGen-1.0"
    for group in acvp_aft_groups(gen):
        if group["curve"] != curve_acvp or group["preHash"]:
            continue
        tests = [sig_test(acvp_id(gen, group, t), t["message"], t["signature"], True)
                 for t in group["tests"] if int(t["contextLength"]) == 0]
        if tests:
            out.append({"source": acvp_source(gen), "private": group["d"].lower(), "public": group["q"].lower(),
                        "tests": tests})
    ver = "EDDSA-SigVer-1.0"
    for group in acvp_aft_groups(ver):
        if group["curve"] != curve_acvp or group["preHash"]:
            continue
        for t in group["tests"]:
            if t.get("context", ""):
                continue
            out.append({"source": acvp_source(ver), "private": "", "public": t["q"].lower(),
                        "tests": [sig_test(acvp_id(ver, group, t), t["message"], t["signature"], passed(t))]})
    return out


def build_x25519() -> list[dict]:
    file = "x25519_test.json"
    return [{"id": f"wycheproof-x25519-{t['tcId']}", "source": wycheproof_source(file), "private": t["private"],
             "public": t["public"], "shared": t["shared"], "valid": valid}
            for _, t, valid in wycheproof_records(wycheproof(file))]


def build_ecdh() -> list[dict]:
    out = []
    for curve in ("secp256r1", "secp384r1", "secp521r1"):
        file = f"ecdh_{curve}_ecpoint_test.json"
        kept = [(t, valid) for _, t, valid in wycheproof_records(wycheproof(file)) if t["public"].startswith("04")]
        for t, valid in kept[:300]:
            out.append({"id": f"wycheproof-ecdh_{curve}-{t['tcId']}", "source": wycheproof_source(file),
                        "curve": CURVES[curve], "private": t["private"], "public": t["public"],
                        "shared": t["shared"], "valid": valid})
    return out


def build_rsa_verify() -> list[dict]:
    out = []
    plain = [f"rsa_signature_{bits}_sha{sha}_test.json" for bits in (2048, 3072, 4096) for sha in (256, 384, 512)]
    plain += ["rsa_signature_2048_sha3_256_test.json", "rsa_signature_3072_sha3_384_test.json"]
    pss = ["rsa_pss_2048_sha256_mgf1_32_test.json", "rsa_pss_3072_sha256_mgf1_32_test.json",
           "rsa_pss_4096_sha256_mgf1_32_test.json", "rsa_pss_2048_sha384_mgf1_48_test.json",
           "rsa_pss_4096_sha384_mgf1_48_test.json", "rsa_pss_4096_sha512_mgf1_64_test.json"]
    for files, is_pss in ((plain, False), (pss, True)):
        for file in files:
            budget = 25
            for group in wycheproof(file)["testGroups"]:
                tests = []
                for t in group["tests"]:
                    if budget and t["result"] != "acceptable":
                        budget -= 1
                        tests.append(sig_test(f"wycheproof-{file.removesuffix('_test.json')}-{t['tcId']}", t["msg"],
                                              t["sig"], t["result"] == "valid"))
                if tests:
                    out.append({"source": wycheproof_source(file), "n": group["publicKey"]["modulus"].lower(),
                                "e": group["publicKey"]["publicExponent"].lower(), "pss": is_pss,
                                "hash": HASH_NAMES[group["sha"]], "tests": tests})
    for name in ("RSA-SigVer-FIPS186-5", "RSA-SigGen-FIPS186-5"):
        for group in acvp(name)["testGroups"]:
            hash_name = HASH_NAMES.get(group["hashAlg"])
            is_pss = group["sigType"] == "pss"
            # SP800-106 groups sign a randomized message hash, not a plain PKCS#1 / PSS signature
            if (hash_name is None or int(group["modulo"]) < 2048 or group.get("conformance") == "SP800-106"
                    or not (group["sigType"] == "pkcs1v1.5"
                            or (is_pss and group["maskFunction"] == "mgf1"
                                and int(group["saltLen"]) == DIGEST_BYTES[hash_name]))):
                continue
            out.append({"source": acvp_source(name), "n": group["n"].lower(), "e": norm_hex_int(group["e"]),
                        "pss": is_pss, "hash": hash_name,
                        "tests": [sig_test(acvp_id(name, group, t), t["message"], t["signature"],
                                           passed(t)) for t in group["tests"]]})
    return out


def build_rsa_pkcs1_sign(registry_zip: bytes) -> list[dict]:
    text = zipfile.ZipFile(io.BytesIO(registry_zip)).read("SigGen15_186-3.txt").decode()
    out = []
    key = {}
    mod = 0
    taken: dict[tuple[int, str], int] = {}
    current: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        m = re.fullmatch(r"\[mod = (\d+)\]", line)
        if m:
            mod = int(m.group(1))
            key = {}
        elif "=" in line and not line.startswith("#"):
            field, value = (p.strip() for p in line.split("=", 1))
            if field in ("n", "e", "d"):
                key[field] = norm_hex_int(value) if field == "e" else value.lower()
            elif field in ("SHAAlg", "Msg", "S"):
                current[field] = value
                if field == "S":
                    hash_name = HASH_NAMES[current["SHAAlg"]]
                    count = taken.get((mod, hash_name), 0)
                    if hash_name in ("SHA-224", "SHA-256", "SHA-384", "SHA-512") and count < 5:
                        taken[(mod, hash_name)] = count + 1
                        out.append({"id": f"cavp-siggen15-{len(out) + 1}",
                                    "source": "NIST CAVP 186-3rsatestvectors.zip SigGen15_186-3.txt",
                                    "n": key["n"], "e": key["e"], "d": key["d"], "hash": hash_name,
                                    "msg": current["Msg"].lower(), "sig": current["S"].lower()})
                    current = {}
    return out


def build_rsa_oaep() -> list[dict]:
    out = []
    for suffix in ("2048_sha256_mgf1sha256", "2048_sha256_mgf1sha1", "2048_sha384_mgf1sha384",
                   "2048_sha512_mgf1sha512", "3072_sha256_mgf1sha256", "4096_sha256_mgf1sha256",
                   "4096_sha512_mgf1sha512"):
        file = f"rsa_oaep_{suffix}_test.json"
        for group in wycheproof(file)["testGroups"]:
            tests = [{"id": f"wycheproof-rsa_oaep_{suffix}-{t['tcId']}", "label": t["label"], "msg": t["msg"],
                      "ct": t["ct"], "valid": t["result"] == "valid"}
                     for t in group["tests"] if t["result"] != "acceptable"]
            out.append({"source": wycheproof_source(file), "private_key_pkcs8": group["privateKeyPkcs8"],
                        "hash": HASH_NAMES[group["sha"]], "mgf_hash": HASH_NAMES[group["mgfSha"]], "tests": tests})
    return out


def build_rsa_pkcs1_decrypt() -> list[dict]:
    out = []
    for bits in (2048, 3072, 4096):
        file = f"rsa_pkcs1_{bits}_test.json"
        for group in wycheproof(file)["testGroups"]:
            tests = [{"id": f"wycheproof-rsa_pkcs1_{bits}-{t['tcId']}", "label": "", "msg": t["msg"], "ct": t["ct"],
                      "valid": t["result"] == "valid"}
                     for t in group["tests"] if t["result"] != "acceptable"]
            if tests:
                out.append({"source": wycheproof_source(file), "private_key_pkcs8": group["privateKeyPkcs8"],
                            "tests": tests})
    return out


def build_pqc_keygen(name: str, kem: bool) -> list[dict]:
    out = []
    for group in acvp_aft_groups(name):
        for t in group["tests"][:5]:
            seed = t["d"] + t["z"] if kem else t["seed"]
            out.append({"id": acvp_id(name, group, t), "source": acvp_source(name),
                        "parameter_set": group["parameterSet"], "seed": seed.lower(),
                        "pk": (t["ek"] if kem else t["pk"]).lower(), "sk": (t["dk"] if kem else t["sk"]).lower()})
    return out


def build_ml_kem_decaps() -> list[dict]:
    out = []
    for size in (512, 768, 1024):
        file = f"mlkem_{size}_test.json"
        kept = [(g, t, valid) for g, t, valid in wycheproof_records(wycheproof(file)) if "seed" in t and "c" in t]
        for g, t, valid in kept[:60]:
            out.append({"id": f"wycheproof-mlkem_{size}-{t['tcId']}", "source": wycheproof_source(file),
                        "parameter_set": g["parameterSet"], "seed": t["seed"], "c": t["c"], "k": t.get("K", ""),
                        "valid": valid})
    return out


def build_pqc_verify(name: str, oids: dict[str, str], wycheproof_files: tuple[str, ...]) -> list[dict]:
    out = []
    for file in wycheproof_files:
        doc = wycheproof(file)
        kept = 0
        for group in doc["testGroups"]:
            tests = []
            for t in group["tests"]:
                if "ctx" in t or kept >= 20:
                    continue
                kept += 1
                tests.append(sig_test(f"wycheproof-{file.removesuffix('_test.json')}-{t['tcId']}", t["msg"],
                                      t["sig"], t["result"] == "valid"))
            if tests:
                out.append({"source": wycheproof_source(file), "parameter_set": doc["algorithm"],
                            "public_key_spki": group["publicKeyDer"], "tests": tests})
    for group in acvp_aft_groups(name):
        if group["signatureInterface"] != "external" or group["preHash"] != "pure":
            continue
        for t in group["tests"]:
            if t.get("context", ""):
                continue
            out.append({"source": acvp_source(name), "parameter_set": group["parameterSet"],
                        "public_key_spki": spki(oids[group["parameterSet"]], t["pk"]),
                        "tests": [sig_test(acvp_id(name, group, t), t["message"], t["signature"], passed(t))]})
    return out


def main():
    repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    cargo_home = os.environ.get("CARGO_HOME") or os.path.expanduser("~/.cargo")
    registries = sorted(glob.glob(os.path.join(cargo_home, "registry", "src", "index.crates.io-*")))
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--openssl-tarball", default=os.path.join(repo, "resources", "tarballs", "openssl-3.1.2.tar.gz"))
    parser.add_argument("--cargo-registry", default=registries[0] if len(registries) == 1 else None)
    parser.add_argument("--out", default=os.path.join(repo, "test_data", "vectors", "kat", "sources"))
    parser.add_argument("--cache-dir", default=os.path.join(repo, "target", "kat_downloads"))
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
    global CACHE_DIR
    CACHE_DIR = args.cache_dir

    with tarfile.open(args.openssl_tarball) as tar:
        def stanzas(name):
            member = tar.extractfile(OPENSSL_DATA + name)
            if member is None:
                fatal(f"{name} not found in the OpenSSL tarball")
            return parse_openssl_stanzas(member.read().decode())

        openssl_mac = stanzas(OPENSSL_MAC)
        openssl_cipher = stanzas(OPENSSL_CIPHER)
        openssl_md = stanzas(OPENSSL_MD)
        openssl_chacha = stanzas(OPENSSL_CHACHA)
        openssl_wrap = stanzas(OPENSSL_WRAP)
        openssl_hkdf = stanzas(OPENSSL_HKDF)
        openssl_pbkdf2 = stanzas(OPENSSL_PBKDF2)

    gcm = build_gcm(openssl_cipher, args.cargo_registry)
    files = {
        "aes_cmac.json": build_cmac(openssl_mac, args.cargo_registry),
        "aes_gcm.json": gcm,
        "aes_gmac.json": build_gmac(openssl_mac, gcm),
        "shake256.json": build_shake(openssl_md),
        "aes_ecb.json": build_aes_ecb_cbc("ACVP-AES-ECB-1.0"),
        "aes_cbc.json": build_aes_ecb_cbc("ACVP-AES-CBC-1.0"),
        "aes_cbc_pkcs5.json": build_aes_cbc_pkcs5(),
        "aes_xts.json": build_aes_xts(),
        "chacha20.json": build_chacha20(openssl_chacha),
        "aes_gcm_siv.json": build_aes_gcm_siv(),
        "chacha20_poly1305.json": build_chacha20_poly1305(openssl_chacha),
        "aes_kw.json": build_wrap("ACVP-AES-KW-1.0", "aes_wrap_test.json",
                                  {"id-aes128-wrap", "id-aes192-wrap", "id-aes256-wrap"}, openssl_wrap, 1024, 4),
        "aes_kwp.json": build_wrap("ACVP-AES-KWP-1.0", "aes_kwp_test.json",
                                   {"id-aes128-wrap-pad", "id-aes192-wrap-pad", "id-aes256-wrap-pad"},
                                   openssl_wrap, 1024, 4),
        "aes_ff1.json": build_aes_ff1(),
        "hmac.json": build_hmac(openssl_mac),
        "hkdf.json": build_hkdf(openssl_hkdf),
        "pbkdf2.json": build_pbkdf2(openssl_pbkdf2),
        "sha.json": build_sha(openssl_md),
        "ecdsa_verify.json": build_ecdsa_verify(("secp256r1", "secp384r1", "secp521r1")) + build_ecdsa_acvp_verify(),
        "ecdsa_secp256k1_verify.json": build_ecdsa_verify(("secp256k1",)),
        "ecdsa_p256_rfc6979_sign.json": build_ecdsa_p256_sign(),
        "ed25519.json": build_eddsa("ED-25519", "ed25519_test.json"),
        "ed448.json": build_eddsa("ED-448", "ed448_test.json"),
        "x25519.json": build_x25519(),
        "ecdh.json": build_ecdh(),
        "rsa_verify.json": build_rsa_verify(),
        "rsa_pkcs1_sign.json": build_rsa_pkcs1_sign(
            fetch("cavp/186-3rsatestvectors.zip", CAVP_RSA_URL, args.cache_dir)),
        "rsa_oaep.json": build_rsa_oaep(),
        "rsa_pkcs1_decrypt.json": build_rsa_pkcs1_decrypt(),
        "ml_kem_keygen.json": build_pqc_keygen("ML-KEM-keyGen-FIPS203", True),
        "ml_kem_decaps.json": build_ml_kem_decaps(),
        "ml_dsa_keygen.json": build_pqc_keygen("ML-DSA-keyGen-FIPS204", False),
        "ml_dsa_verify.json": build_pqc_verify("ML-DSA-sigVer-FIPS204", ML_DSA_OIDS,
                                               tuple(f"mldsa_{n}_verify_test.json" for n in (44, 65, 87))),
        "slh_dsa_verify.json": build_pqc_verify("SLH-DSA-sigVer-FIPS205", SLH_DSA_OIDS, ()),
    }
    # SLH-DSA sigGen has no runnable consumer (see README gaps); fetched so its pin stays verified.
    fetch("acvp/SLH-DSA-sigGen-FIPS205",
          ACVP_URL.format(commit=ACVP_COMMIT, name="SLH-DSA-sigGen-FIPS205"), args.cache_dir)
    os.makedirs(args.out, exist_ok=True)
    for name, records in files.items():
        if not records:
            fatal(f"{name}: no vector produced")
        path = os.path.join(args.out, name)
        with open(path, "w") as f:
            json.dump(records, f, indent=1)
            f.write("\n")
        if os.path.getsize(path) > MAX_OUTPUT_BYTES:
            fatal(f"{name}: {os.path.getsize(path)} bytes > {MAX_OUTPUT_BYTES}")
        count = sum(len(r["tests"]) if "tests" in r else 1 for r in records)
        print(f"{name}: {count} vectors")


if __name__ == "__main__":
    main()
