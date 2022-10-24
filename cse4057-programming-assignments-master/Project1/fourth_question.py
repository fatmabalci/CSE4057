# Authors: Fatma Balcı

from helper import *
from second_question import key_k1, key_k2
from Crypto.Util import Counter
from logger import log

# Temporary output files, you may change to see each of them if you prefer
file_name = "fourth_question_input.txt"
output_file_name = "fourth_question_input.txt.encrypted"
verification_file_name = "fourth_question_verification.txt"

log("AES (128 bit key) in CBC mode encryption is started!")
encrypt_file_cbc_mode(key_k1, file_name, '_i')
log("AES (128 bit key) in CBC mode encryption is done!")
log("AES (128 bit key) in CBC mode decryption is started!")
decrypt_file_cbc_mode(key_k1, output_file_name, verification_file_name + '_i')
log("AES (128 bit key) in CBC mode decryption is done!")

log("AES (256 bit key) in CBC mode encryption is started!")
encrypt_file_cbc_mode(key_k2, file_name, '_ii')
log("AES (256 bit key) in CBC mode encryption is done!")
log("AES (256 bit key) in CBC mode decryption is started!")
decrypt_file_cbc_mode(key_k2, output_file_name, verification_file_name + '_ii')
log("AES (256 bit key) in CBC mode decryption is done!")

# Get a random nonce value
nonce = Random.get_random_bytes(8)
countf = Counter.new(64, nonce) 

log("AES (256 bit key) in CTR mode encryption is started!")
encrypt_file_ctr_mode(key_k2, file_name, countf, '_iii')
log("AES (256 bit key) in CTR mode encryption is done!")
log("AES (256 bit key) in CTR mode decryption is started!")
decrypt_file_ctr_mode(key_k2, output_file_name, verification_file_name + '_iii', countf)
log("AES (256 bit key) in CTR mode decryption is done!")


log("AES (128 bit key) in CBC mode encryption with different IV value is started!")
encrypt_file_cbc_mode(key_k1, file_name, '_i_new')
log("AES (128 bit key) in CBC mode encryption with different IV value is done!")
log("AES (128 bit key) in CBC mode decryption with different IV value is started!")
decrypt_file_cbc_mode(key_k1, output_file_name, verification_file_name + '_i_new')
log("AES (128 bit key) in CBC mode decryption with different IV value is done!")