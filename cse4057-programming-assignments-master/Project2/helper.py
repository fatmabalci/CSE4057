
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

# This function is implemented to sign the certificate by server
# returns the signed certificate


def sign(user_name):
    with open(f"{user_name}_public.txt", "r") as public_txt:
        user_public_key = public_txt.read()
    
    sha_digest = SHA256.new()
    sha_digest.update(user_public_key.encode('utf-8'))

    with open(f"server_private.pem", "r") as private_pem:
        private_key = RSA.import_key(private_pem.read())

    sign_pkcs = PKCS1_v1_5.new(private_key)
    certificate = sign_pkcs.sign(sha_digest)

    print(f"Signed certificate digest {certificate.hex()}")
    return certificate

# This function is implemented to verify the signed certificate


def verify(user_name, certificate):
    with open(f"{user_name}_public.txt", "r") as public_txt:
        user_public_key = public_txt.read()
    
    sha_digest = SHA256.new()
    sha_digest.update(user_public_key.encode('utf-8'))

    with open(f"server_public.txt", "r") as public_txt:
        public_key = RSA.import_key(public_txt.read())

    verify_pkcs = PKCS1_v1_5.new(public_key)

    is_verified = verify_pkcs.verify(sha_digest, certificate)

    return is_verified


def generate_keys(user_name):
    key = RSA.generate(2048)

    f = open(f'{user_name}_private.pem', 'wb')
    f.write(key.export_key('PEM'))
    f.close()

    public_key = key.publickey().export_key()

    f = open(f'{user_name}_public.txt', 'wb')
    f.write(public_key)
    f.close()

def save_certificate(user_name, certificate_hex):
    f = open(f'{user_name}_certificate.txt', 'w')
    print(certificate_hex)
    f.write(certificate_hex)
    f.close()

def import_certificate(user_name):
    with open(f"{user_name}_certificate.txt", "r") as hex_txt:
        hex = hex_txt.read()
    
    certificate = bytes.fromhex(hex)

    return certificate

def encrypt_text(file_name, public_key, data):
    # open the file to write into
    file_out = open(file_name, "wb")
    # generate random session key
    session_key = get_random_bytes(16)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    # encrypt
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    # write into file
    [ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
    file_out.close()

def decrypt_text(file_name, private_key):
    # open the file that we will read up on
    file_in = open(file_name, "rb")

    # get the details from the file
    enc_session_key, nonce, tag, ciphertext = \
    [ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    # get session key as prior for the decrypt & verify
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    # decrypt
    data = cipher_aes.decrypt_and_verify(ciphertext, tag).decode("utf-8")

    return data

# to uncomment: Select all commanded line and press "ctrl" + "/"

#-------------------------------------------------------------------------------
# for 3rd Question

# import random
#
# class Key:
#
# 	def __init__(self, key=''):
# 		if key == '':
# 			self.key= self.generate()
# 		else:
# 			self.key = key.lower()
#
# 	def verify(self):
# 		score = 0
# 		check_digit = self.key[0]
# 		check_digit_count = 0
# 		chunks = self.key.split('-')
# 		for chunk in chunks:
# 			if len(chunk) != 4:
# 				return False
# 			for char in chunk:
# 				if char == check_digit:
# 					check_digit_count += 1
# 				score += ord(char)
# 		if score == 1772 and check_digit_count == 5:
# 			return True
# 		return False
#
# 	def generate(self):
# 		key = ''
# 		chunk = ''
# 		check_digit_count = 0
# 		alphabet = 'abcdefghijklmnopqrstuvwxyz1234567890'
# 		while True:
# 			while len(key) < 25:
# 				char = random.choice(alphabet)
# 				key += char
# 				chunk += char
# 				if len(chunk) == 4:
# 					key += '-'
# 					chunk = ''
# 			key = key[:-1]
# 			if Key(key).verify():
# 				return key
# 			else:
# 				key = ''
#
# 	def __str__(self):
# 		valid = 'Invalid'
# 		if self.verify():
# 			valid = 'Valid'
# 		return self.key.upper() + ':' + valid


#--------------------------------------------------------------------------------------
#for 4th question

#!/usr/bin/env python3
#
# This is a simple script to encrypt a message using AES
# with CBC mode in Python 3.
# Before running it, you must install pycryptodome:
#
# $ python -m pip install PyCryptodome
#
# Author.: José Lopes
# Date...: 2019-06-14
# License: MIT
##

#
# from hashlib import md5
# from base64 import b64decode
# from base64 import b64encode
#
# from Crypto.Cipher import AES
# from Crypto.Random import get_random_bytes
# from Crypto.Util.Padding import pad, unpad
#
#
# class AESCipher:
#     def __init__(self, key):
#         self.key = md5(key.encode('utf8')).digest()
#
#     def encrypt(self, data):
#         iv = get_random_bytes(AES.block_size)
#         self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
#         return b64encode(iv + self.cipher.encrypt(pad(data.encode('utf-8'),
#             AES.block_size)))
#
#     def decrypt(self, data):
#         raw = b64decode(data)
#         self.cipher = AES.new(self.key, AES.MODE_CBC, raw[:AES.block_size])
#         return unpad(self.cipher.decrypt(raw[AES.block_size:]), AES.block_size)
#
#
# if __name__ == '__main__':
#     print('TESTING ENCRYPTION')
#     msg = input('Message...: ')
#     pwd = input('Password..: ')
#     print('Ciphertext:', AESCipher(pwd).encrypt(msg).decode('utf-8'))
#
#     print('\nTESTING DECRYPTION')
#     cte = input('Ciphertext: ')
#     pwd = input('Password..: ')
#     print('Message...:', AESCipher(pwd).decrypt(cte).decode('utf-8'))



#------------------------------
#same as above for 4th question

# from hashlib import md5
#
# from Crypto.Cipher import AES
# from Crypto.Random import get_random_bytes
# from Crypto.Util.Padding import pad, unpad
#
#
# class AESCipher:
#     def __init__(self, key):
#         password = key.encode('utf-8')
#         self.key = md5(password).digest()
#
#     def encrypt(self, data):
#         vector = get_random_bytes(AES.block_size)
#         encryption_cipher = AES.new(self.key, AES.MODE_CBC, vector)
#         return vector + encryption_cipher.encrypt(pad(data, AES.block_size))
#
#     def decrypt(self, data):
#         file_vector = data[:AES.block_size]
#         decryption_cipher = AES.new(self.key, AES.MODE_CBC, file_vector)
#         return unpad(decryption_cipher.decrypt(data[AES.block_size:]), AES.block_size)
#
#
# if __name__ == '__main__':
#     print('TESTING ENCRYPTION')
#     msg = "helloWorld".encode('utf-8')
#     pwd = "password"
#
#     encrypted = AESCipher(pwd).encrypt(msg)
#     print('Ciphertext:', encrypted)
#     print('\nTESTING DECRYPTION')
#     decrypted = AESCipher(pwd).decrypt(encrypted).decode('utf-8')
#     print("Original data: ", msg.decode('utf-8'))
#     print("Decripted data:", decrypted)
#     assert msg.decode('utf-8') == decrypted



#----------------------------------------------------------------------------------

#for 5th question
#
# #!/usr/bin/env python3
# from hashlib import sha256
# import os
#
# # Takes the path (as a string) to a SHA256SUMS file and a list of paths to
# # local files. Returns true only if all files' checksums are present in the
# # SHA256SUMS file and their checksums match
# def integrity_is_ok( sha256sums_filepath, local_filepaths ):
#
#     # first we parse the SHA256SUMS file and convert it into a dictionary
#     sha256sums = dict()
#     with open( sha256sums_filepath ) as fd:
#         for line in fd:
#             # sha256 hashes are exactly 64 characters long
#             checksum = line[0:64]
#
#             # there is one space followed by one metadata character between the
#             # checksum and the filename in the `sha256sum` command output
#             filename = os.path.split( line[66:] )[1].strip()
#             sha256sums[filename] = checksum
#
#     # now loop through each file that we were asked to check and confirm its
#     # checksum matches what was listed in the SHA256SUMS file
#     for local_file in local_filepaths:
#
#         local_filename = os.path.split( local_file )[1]
#
#         sha256sum = sha256()
#         with open( local_file, 'rb' ) as fd:
#             data_chunk = fd.read(1024)
#             while data_chunk:
#                 sha256sum.update(data_chunk)
#                 data_chunk = fd.read(1024)
#
#         checksum = sha256sum.hexdigest()
#         if checksum != sha256sums[local_filename]:
#             return False
#
#     return True
#
# if __name__ == '__main__':
#
#     script_dir = os.path.split( os.path.realpath(__file__) )[0]
#     sha256sums_filepath = script_dir + '/SHA256SUMS'
#     local_filepaths = [ script_dir + '/MANIFEST' ]
#
#     if integrity_is_ok( sha256sums_filepath, local_filepaths ):
#         print( "INFO: Checksum OK" )
#     else:
#         print( "ERROR: Checksum Invalid" )
#