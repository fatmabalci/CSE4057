import hashlib
from helper import *
from Crypto.PublicKey import RSA
from logger import log

# Lorem ipsum text above 1000 characters
text = """
Lorem ipsum dolor sit amet, consectetur adipiscing elit. In interdum risus eget varius finibus. Nulla vestibulum sapien eu ex sollicitudin gravida. Nullam euismod fringilla ornare. Nulla a ipsum et elit varius auctor vel vel felis. Sed aliquam purus a rhoncus imperdiet. Morbi eu nisi ante. Nulla facilisi. Donec venenatis lorem quis lacus pellentesque molestie.
Praesent vel pellentesque felis. Donec molestie ut ipsum vitae pharetra. Donec nisi leo, dignissim vel felis ac, volutpat commodo justo. Pellentesque porttitor molestie quam, eget lacinia nisl. Duis turpis odio, feugiat vel tristique eu, rutrum non nulla. Duis ultricies non velit a tincidunt. Phasellus egestas ligula quis ipsum pulvinar tincidunt. Aliquam vitae est lobortis, convallis ipsum lacinia, mollis elit. Ut viverra tincidunt sem, et placerat tellus consequat eget. Sed non posuere nisl. Aenean eget elit viverra, dictum eros non, convallis felis.
Proin tincidunt lacus quam, nec dignissim nulla lobortis at. Etiam sit amet ornare dui, eu facilisis tellus. Praesent quis placerat arcu. Nullam tincidunt lacinia ex, dictum imperdiet augue facilisis quis. Nam ullamcorper ligula iaculis velit varius convallis. Duis in eros sed justo vulputate aliquam elementum quis mauris. Aliquam hendrerit risus eu diam tempus, sed eleifend elit tincidunt. Nulla hendrerit lacus sit amet ante facilisis elementum. Aliquam vitae ipsum ullamcorper, dictum mi in, facilisis metus. Integer vel orci nisi. Aliquam dignissim erat in viverra pretium.
Curabitur a varius dolor. Vestibulum ut sapien vel nunc ultricies pulvinar sed cursus leo. Integer at nisl eget magna varius varius. Morbi elementum volutpat mi sed imperdiet. Phasellus at bibendum urna. Curabitur bibendum commodo sem at venenatis. Nullam sed mauris id metus porta tempus.
Pellentesque eu purus a orci congue sodales. Pellentesque imperdiet orci nunc, sed feugiat neque faucibus in. Nulla laoreet ante id efficitur iaculis. Nunc ut neque ac ex cursus vehicula eget at nisi. Donec placerat nibh at risus.
"""

# we get the hashed string
hashed_string = hashlib.sha256(text.encode('utf-8')).hexdigest()
log("Original message")
print(100 * "-")
print(text)
print(100 * "-")
log(f"SHA256 hash algorithm has been applied to the message, value: {hashed_string}")
print(100 * "-")

# Import needed values
ka_public_key_value = RSA.import_key(open("ka_public.pem").read())
ka_private_key_value = RSA.import_key(open("ka_private.pem").read())

# encrypt the hashed value
encrypt("encrypted_hash_string.bin", ka_public_key_value, hashed_string.encode('utf-8'), "Hashed string")
print(100 * "-")
# decrypt the hashed value
decrypt("encrypted_hash_string.bin", ka_private_key_value, "Hashed string")