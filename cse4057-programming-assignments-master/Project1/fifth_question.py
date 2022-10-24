# Authors: Fatma Balcı

import hmac
import hashlib
from second_question import key_k1, key_k2
from logger import log

# define a message
message = "INFORMATION SYSTEMS SECURITY".encode('utf-8')

# create HMAC SHA256 message
hmac_obj = hmac.new(key_k1, msg=message, digestmod=hashlib.sha256)

# print the output
log(hmac_obj.hexdigest().upper())

# apply this to k2
hmac_obj_2 = hmac.new(key_k1, msg=key_k2, digestmod=hashlib.sha256)

# print the output
log(hmac_obj_2.hexdigest().upper())