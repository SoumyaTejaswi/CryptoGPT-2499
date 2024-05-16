# aes_module.py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

DELIMITER = b'||'  # Use a unique delimiter

import base64

def encrypt(plaintext, key):
    plaintext_bytes = plaintext.encode()
    key_bytes = key.encode()
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    ciphertext_bytes = cipher.encrypt(pad(plaintext_bytes, AES.block_size))

    # Encode the IV and ciphertext to base64
    iv_base64 = base64.b64encode(iv).decode()
    ciphertext_base64 = base64.b64encode(ciphertext_bytes).decode()

    # Concatenate the base64 encoded IV and ciphertext with the delimiter
    return iv_base64 + DELIMITER.decode() + ciphertext_base64


def decrypt(iv_ciphertext, key):
    # Decode iv_ciphertext only if it's bytes
    if isinstance(iv_ciphertext, bytes):
        try:
            iv_ciphertext = iv_ciphertext.decode()  # Convert bytes to string with utf-8
        except UnicodeDecodeError:
            raise ValueError("Invalid iv_ciphertext encoding. Use utf-8 or compatible encoding.")

    # Decode the delimiter if it's in bytes format
    delimiter = DELIMITER.decode() if isinstance(DELIMITER, bytes) else DELIMITER

    # Check if iv_ciphertext is still bytes after decoding
    if isinstance(iv_ciphertext, bytes):
        raise TypeError("Invalid iv_ciphertext format. Should be a decoded string.")

    # Split using the delimiter, but limit the split to only 1 occurrence
    iv_base64, ciphertext_base64 = iv_ciphertext.split(delimiter, 1)
    
    # Decode base64 encoded IV and ciphertext to bytes
    iv = base64.b64decode(iv_base64)
    ciphertext = base64.b64decode(ciphertext_base64)

    key_bytes = key.encode()
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    decrypted_bytes = cipher.decrypt(ciphertext)
    plaintext_bytes = unpad(decrypted_bytes, AES.block_size)
    return plaintext_bytes.decode()