import struct, base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_private_key, load_pem_private_key
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


 
def parse_blob(data: bytes) -> dict:
    # [0-1]  version (uint16 BE)
    # [2-3]  enc_pass_len (uint16 BE)
    # [4..4+enc_pass_len] RSA-encrypted passphrase
    # [4+enc_pass_len .. +2] pem_len (uint16 BE)
    # [4+enc_pass_len+2 .. +pem_len] PEM bytes
    version      = data[0:2]
    enc_pass_len = struct.unpack_from('>H', data, 2)[0]
    enc_pass     = data[4:4 + enc_pass_len]
    pem_len      = struct.unpack_from('>H', data, 4 + enc_pass_len)[0]
    pem          = data[4 + enc_pass_len + 2 : 4 + enc_pass_len + 2 + pem_len]
 
    print(f"[*] version:      {version.hex()}")
    print(f"[*] enc_pass_len: {enc_pass_len}")
    print(f"[*] pem_len:      {pem_len}")
 
    return {"enc_pass": enc_pass, "pem": pem}
 
 
def parse_pkcs8_pem(pem: bytes) -> dict:
    # Decode base64 content between PEM headers
    lines = pem.decode('ascii').strip().splitlines()
    b64 = ''.join(l for l in lines if not l.startswith('---'))
    der = bytearray(base64.b64decode(b64))
 
    # The app writes 2 spurious bytes (0x0c 0x07) before the
    # encryption algorithm OID. We patch them out and fix enclosing lengths.
    # Corrupt bytes are at offset 61 in the DER.
    patched = der[:61] + der[63:]
    patched[2]  = 0xea  # root SEQUENCE length: 236 → 234
    patched[4]  = 0x55  # inner SEQUENCE length: 87 → 85
    patched[17] = 0x48  # alg params SEQUENCE length: 74 → 72
 
    # Extract PBKDF2 params and encrypted payload from patched DER
    # salt: OCTET STRING at offset 33, length 8
    salt       = bytes(patched[35:43])
    # iterations: INTEGER at offset 43, length 2
    iterations = struct.unpack_from('>H', patched, 45)[0]
    # IV: OCTET STRING at offset 72, length 16
    iv         = bytes(patched[74:90])
    # encrypted data: OCTET STRING at offset 90, length 144
    ciphertext = bytes(patched[93:93+144])
 
    print(f"[*] salt:       {salt.hex()}")
    print(f"[*] iterations: {iterations}")
    print(f"[*] iv:         {iv.hex()}")
    print(f"[*] ciphertext: {len(ciphertext)} bytes")
 
    return {"salt": salt, "iterations": iterations, "iv": iv, "ciphertext": ciphertext}
 
 
def pkcs7_unpad(data: bytes) -> bytes:
    pad = data[-1]
    return data[:-pad]
 
 
def KeyDecrypt(rsa_key_hex: str, cipher_data_hex: str):
    rsa_key_bytes = bytes.fromhex(rsa_key_hex)
    cipher_data   = bytes.fromhex(cipher_data_hex)
 
    # Step 1: parse outer blob
    blob = parse_blob(cipher_data)
 
    # Step 2: load RSA private key (PEM or DER, auto-detected)
    if rsa_key_bytes.lstrip().startswith(b'-----'):
        rsa_key = load_pem_private_key(rsa_key_bytes, password=None)
    else:
        rsa_key = load_der_private_key(rsa_key_bytes, password=None)
 
    # Step 3: RSA decrypt the passphrase (PKCS#1 v1.5)
    passphrase = rsa_key.decrypt(blob['enc_pass'], padding.PKCS1v15())
    print(f"\n[*] passphrase ({len(passphrase)} bytes): {passphrase.hex()}")
 
    # Step 4: parse the corrupt PKCS#8 PEM manually
    params = parse_pkcs8_pem(blob['pem'])
 
    # Step 5: derive AES-256 key via PBKDF2-HMAC-SHA256
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=params['salt'],
        iterations=params['iterations'],
    )
    aes_key = kdf.derive(passphrase)
    print(f"[*] aes_key: {aes_key.hex()}")
 
    # Step 6: AES-256-CBC decrypt
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(params['iv']))
    dec = cipher.decryptor()
    plaintext = pkcs7_unpad(dec.update(params['ciphertext']) + dec.finalize())
    print(f"\n[+] Decrypted private key DER ({len(plaintext)} bytes):")
    print(plaintext.hex())
 
    # Step 7: load and export as unencrypted PEM
    private_key = load_der_private_key(plaintext, password=None)
    result_pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    return result_pem
 
 