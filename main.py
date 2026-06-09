from RSADecryptor import *
from keyDecryptor import *
import argparse

# Arguments
parser = argparse.ArgumentParser()
parser.add_argument("-esk", "--encriptedRSA", required=False, help="Encrypted RSA key.")
parser.add_argument("-hpass", "--hardwarePassword", required=False, default="", help="Hardware password of the PLC. Empty string "" by default.")
parser.add_argument("-rsa", "--RSAkey", required=False, help="RSA decrypted key in hex-PEM format.")
parser.add_argument("-pk", "--privateKey", required=False, help="Passphrase + Private encrypted key.")

args = parser.parse_args()


if args.encriptedRSA:
    rsa_key = RSADecrypt(bytes.fromhex(args.encriptedRSA), args.hardwarePassword)
    print(f"\n[+] Decrypted ({len(rsa_key)} bytes):\n{rsa_key.hex()}")
elif args.RSAkey and args.privateKey:
    private_key = KeyDecrypt(args.RSAkey, args.privateKey)
    print(f"\n[+] Private key PEM:\n{private_key.decode()}")
else:
    print("[x] ERROR: Please specify a valid combination of arguments")


