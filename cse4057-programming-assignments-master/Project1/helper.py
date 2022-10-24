# Authors: Fatma Balcı

import base64, os
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import struct
from logger import log
from Crypto import Random

# compress the public key into hexadecimals
def compress(pubKey):
    return hex(pubKey.x) + hex(pubKey.y % 2)[2:]

# reference https://pycryptodome.readthedocs.io/en/latest/src/examples.html
def generate_secret_key_for_AES_cipher(length_in_bytes):
    # set key length
	key_length = length_in_bytes
    # create the secret key with derivation
	secret_key = os.urandom(key_length)
    # encode the secret key so that it should be applicable for the algorithms
	encoded_secret_key = base64.b64encode(secret_key)
	return encoded_secret_key

# this is the method for RSA encryption with AES
def encrypt(file_name, public_key, data, display_name):
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
    log(f"{display_name} has been encrypted into the file {file_name}")

# this is the method for the decryption for RSA encryption
def decrypt(file_name, private_key, display_name):
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
    log(f"{display_name} has been decrypted, value: {data}")


# Reference: https://www.novixys.com/blog/using-aes-encryption-decryption-python-pycrypto/
# This is the method to decrypt a file in CBC mode for AES 
def decrypt_file_cbc_mode(key, filename, verification_file, chunk_size=2048):
    # open the given file
    with open(filename, 'rb') as infile:
        # get file size
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        # get initialization vector
        iv = infile.read(16)
        # create decryptor object with the assets got from file
        decryptor = AES.new(key, AES.MODE_CBC, iv)
        # write into verification file specified
        with open(verification_file, 'wb') as outfile:
            while True:
                # read up on chunk value
                chunk = infile.read(chunk_size)
                if len(chunk) == 0:
                    break
                # decrypt
                outfile.write(decryptor.decrypt(chunk))
            # truncate upon the size
            outfile.truncate(origsize)
 
# This is the method to encrypt a file in CBC mode for AES 
def encrypt_file_cbc_mode(key, filename, suffix, chunk_size=2048):
    # get a name for the file
    output_filename = filename + suffix + '.encrypted'
    # fetch the iv with proper size
    iv = Random.new().read(AES.block_size)
    # log iv value
    log(f"IV value {iv}")
    # create the aes obj for encryption
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    # get file size
    filesize = os.path.getsize(filename)
    # open the file that will be encrypted
    with open(filename, 'rb') as inputfile:
        # open the file that encrypted value will be written into
        with open(output_filename, 'wb') as outputfile:
            # write the size to the file with IV value
            outputfile.write(struct.pack('<Q', filesize))
            outputfile.write(iv)
            while True:
                # read a chunk at a time to write
                chunk = inputfile.read(chunk_size)
                if len(chunk) == 0:
                    break
                # align
                elif len(chunk) % 16 != 0:
                    # align the data
                    chunk += (' ' * (16 - len(chunk) % 16)).encode('utf-8')
                # write to the file
                outputfile.write(encryptor.encrypt(chunk))

# This is the method to encrypt a file in CTR mode for AES 
def encrypt_file_ctr_mode(key, filename, countf, suffix, chunk_size=2048):
    # get a name for the file
    output_filename = filename + suffix + '.encrypted'
    # create the aes obj for encryption
    encryptor = AES.new(key, AES.MODE_CTR, counter=countf)
    # get file size
    filesize = os.path.getsize(filename)
    # open the file that will be encrypted
    with open(filename, 'rb') as inputfile:
        # open the file that encrypted value will be written into
        with open(output_filename, 'wb') as outputfile:
            # write the size to the file with IV value
            outputfile.write(struct.pack('<Q', filesize))
            while True:
                # read a chunk at a time to write
                chunk = inputfile.read(chunk_size)
                if len(chunk) == 0:
                    break
                # align
                elif len(chunk) % 16 != 0:
                    # align the data
                    chunk += (' ' * (16 - len(chunk) % 16)).encode('utf-8')
                # write to the file
                outputfile.write(encryptor.encrypt(chunk))

# This is the method to decrypt a file in CTR mode for AES 
def decrypt_file_ctr_mode(key, filename, verification_file, countf, chunk_size=2048):
    # open the file that will be decrypted
    with open(filename, 'rb') as infile:
        # get file size
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        # get the aes obj for decryption including the reference nonce counter
        decryptor = AES.new(key, AES.MODE_CTR, counter=countf)
        # open the file that decrypted value will be written into
        with open(verification_file, 'wb') as outfile:
            while True:
                # read a chunk at a time to write
                chunk = infile.read(chunk_size)
                if len(chunk) == 0:
                    break
                # write to the file
                outfile.write(decryptor.decrypt(chunk))
            # truncate upon the size
            outfile.truncate(origsize)