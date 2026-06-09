import hashlib
import struct
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def parse_blob(data: bytes) -> dict:
    o = 0
    def ru16(): nonlocal o; v = struct.unpack_from('>H', data, o)[0]; o+=2; return v
    def ru8():  nonlocal o; v = data[o]; o+=1; return v
    def ri32(): nonlocal o; v = struct.unpack_from('>i', data, o)[0]; o+=4; return v
    def ru32(): nonlocal o; v = struct.unpack_from('>I', data, o)[0]; o+=4; return v
    def rb(n):  nonlocal o; v = data[o:o+n]; o+=n; return v

    version          = ru16()
    kdf_algo_version = ru8()
    iterations       = ri32()
    salt_len         = ru16()
    salt             = rb(salt_len)
    aesgcm_version   = ru8()
    key_len          = ru16()
    nonce_len        = ru16()
    tag_len          = ru16()
    tag              = rb(tag_len)
    encoding         = ru8()
    ct_len           = ru32()
    ciphertext       = rb(ct_len)

    print(f"[*] version:          {version}")
    print(f"[*] kdf_algo_version: {kdf_algo_version}")
    print(f"[*] iterations:       {iterations}")
    print(f"[*] salt  ({salt_len}b):     {salt.hex()}")
    print(f"[*] key_len:          {key_len}")
    print(f"[*] nonce_len:        {nonce_len}")
    print(f"[*] tag   ({tag_len}b):     {tag.hex()}")
    print(f"[*] encoding:         {encoding}")
    print(f"[*] ciphertext ({ct_len}b): {ciphertext[:16].hex()}...")

    return {
        "iterations": iterations,
        "salt":       salt,
        "key_len":    key_len,
        "nonce_len":  nonce_len,
        "tag":        tag,
        "ciphertext": ciphertext,
    }


def RSADecrypt(cipher_data: bytes, password: str) -> bytes:
    blob = parse_blob(cipher_data)

    # Step 1: SHA-256(UTF-8(password)) → pwdh
    pwdh = hashlib.sha256(password.encode('utf-8')).digest()
    print(f"\n[*] pwdh: {pwdh.hex()}")

    # Step 2: PBKDF2(HMAC-SHA-256, pwdh, salt, iterations, key_len + nonce_len)
    derive_len = blob['key_len'] + blob['nonce_len']
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=derive_len,
        salt=blob['salt'],
        iterations=blob['iterations'],
    )
    key_material = kdf.derive(pwdh)

    key   = key_material[:blob['key_len']]
    nonce = key_material[blob['key_len']:]

    print(f"[*] key:   {key.hex()}")
    print(f"[*] nonce: {nonce.hex()}")
    print(f"[*] tag:   {blob['tag'].hex()}")

    # Step 3: AES-256-GCM decrypt
    # cryptography's AESGCM expects ciphertext || tag
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, blob['ciphertext'] + blob['tag'], None)

    return plaintext
