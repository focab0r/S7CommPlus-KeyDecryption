# S7CommPlus-KeyDecryption

These scripts are able to decrypt the private key used by S7-1200 PLC. You must have access to the PLC and the corresponding objects/data to perform the decryption. Tested on firmware version V4.7 and TIA Portal v20.

## Usage of the scripts ##

```
usage: main.py [-h] [-esk ENCRIPTEDRSA] [-hpass HARDWAREPASSWORD] [-rsa RSAKEY] [-pk PRIVATEKEY]

options:
  -h, --help            show this help message and exit
  -esk, --encriptedRSA ENCRIPTEDRSA
                        Encrypted RSA key.
  -hpass, --hardwarePassword HARDWAREPASSWORD
                        Hardware password of the PLC. Empty string by default.
  -rsa, --RSAkey RSAKEY
                        RSA decrypted key in hex-PEM format.
  -pk, --privateKey PRIVATEKEY
                        Passphrase + Private encrypted key.
```

1. First of all, decrypt the RSA private key. Use `-esk` and `-hpass` (optional, by default an empty string ""). This will return the decrypted RSA private key.

Example:
```bash
python3 main.py -esk [ENCRYPTED_RSA_KEY]

[SNIP]

[+] Decrypted (1675 bytes):
2d2d2d2d2d[DECRYPTED_RSA_KEY]2d2d2d2d2d0a
```

2. Use the decrypted RSA private key to decrypt the private key. Use `-rsa` to specify the RSA key, and `-pk` to specify the passphrase + the encrypted private key. 

Example:
```bash
python3 main.py -rsa [DECRYPTED_RSA_KEY] -pk [ENCRYPTED_PRIVATE_KEY]

[SNIP]

[+] Private key PEM:
-----BEGIN PRIVATE KEY-----
[DECRYPTED_PRIVATE_KEY]
-----END PRIVATE KEY-----
```

