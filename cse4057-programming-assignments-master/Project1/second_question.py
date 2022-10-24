# Authors: Fatma Balcı

from first_question import *
from helper import *
from logger import log

# Generation of the k1
key_k1 = generate_secret_key_for_AES_cipher(16)

log(f"128 bit K1 symmetric key: {key_k1}")

# Generation of the k2
key_k2 = generate_secret_key_for_AES_cipher(24)

log(f"256 bit K2 symmetric key: {key_k2}")

# Fetch the values created in the first question
ka_public_key_value = RSA.import_key(open("ka_public.pem").read())
ka_private_key_value = RSA.import_key(open("ka_private.pem").read())

# Log the values for later usage
encrypt("encrypted_k1.bin", ka_public_key_value, key_k1, "K1 value")
decrypt("encrypted_k1.bin", ka_private_key_value, "K1 value")

# Log the values for later usage
encrypt("encrypted_k2.bin", ka_public_key_value, key_k2, "K2 value")
decrypt("encrypted_k2.bin", ka_private_key_value, "K2 value")

# 2.b

# Get shared keys with the multiplication of each others private and public values
key_k3_1 = key_kb_private * key_kc_public
key_k3_2 = key_kc_private * key_kb_public

log(f"Kc+ and Kb- symmetric key: {compress(key_k3_1)}", )
log(f"Kb+ and Kc- symmetric key: {compress(key_k3_2)}", )