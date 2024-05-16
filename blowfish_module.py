# blowfish_module.py
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

DELIMITER = b'||'  # Use a unique delimiter

import base64

def encrypt(plaintext, key):
    plaintext_bytes = plaintext.encode()
    key_bytes = key.encode()
    
    # Pad or truncate the key to the required length (between 4 and 56 bytes)
    key_bytes = key_bytes.ljust(56, b'\0')[:56]
    
    cipher = Blowfish.new(key_bytes, Blowfish.MODE_ECB)
    ciphertext_bytes = cipher.encrypt(pad(plaintext_bytes, Blowfish.block_size))
    return base64.b64encode(ciphertext_bytes).decode()

def decrypt(ciphertext, key):
    ciphertext_bytes = base64.b64decode(ciphertext)
    key_bytes = key.encode()
    
    # Pad or truncate the key to the required length (between 4 and 56 bytes)
    key_bytes = key_bytes.ljust(56, b'\0')[:56]
    
    cipher = Blowfish.new(key_bytes, Blowfish.MODE_ECB)
    decrypted_bytes = cipher.decrypt(ciphertext_bytes)
    return unpad(decrypted_bytes, Blowfish.block_size).decode()
