# Authors: Fatma Balcı

from Crypto.PublicKey import RSA
from tinyec import registry
import secrets
from logger import log


# 1) a. Generate an RSA public-private key pair.

# Generate RSA keys and export them to some files to be used later

key = RSA.generate(2048)
ka_private_key = key.export_key()
# Export private key to a pem file
file_out = open("ka_private.pem", "wb")
file_out.write(ka_private_key)
file_out.close()

# Get public Key
ka_public_key = key.publickey().export_key()
# Export public key to a pem file
file_out = open("ka_public.pem", "wb")
file_out.write(ka_public_key)
file_out.close()


# 1) b. Generate two ECDH public-private key pairs.

# Reference; https://github.com/alexmgr/tinyec/blob/master/tinyec/registry.py
curve = registry.get_curve('secp256r1')

# Get a random value from the field curve
key_kb_private = secrets.randbelow(curve.field.n)
key_kb_public = key_kb_private * curve.g

# log(f'Kb private {key_kb_private}')

# log(f'Kb public {key_kb_public}')

# Get a random value from the field curve
key_kc_private = secrets.randbelow(curve.field.n)
key_kc_public = key_kc_private * curve.g
# log(f'Kc private {key_kc_private}')

# log(f'Kc public {key_kc_public}')