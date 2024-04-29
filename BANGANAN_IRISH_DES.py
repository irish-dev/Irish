import os
import binascii
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad

# Create a DES key
def generate_des_key():
    return DES.new(os.urandom(8), DES.MODE_ECB)

# Convert string to byte array
def str_to_byte_array(plaintext):
    return plaintext.encode('utf-8')

# Encryption
def encrypt_des(plaintext):
    des_key = generate_des_key()
    plaintext_bytes = str_to_byte_array(plaintext)
    ciphertext = des_key.encrypt(pad(plaintext_bytes, DES.block_size))
    return ciphertext

# Decryption
def decrypt_des(ciphertext):
    des_key = generate_des_key()
    decrypted_plaintext = des_key.decrypt(ciphertext)
    return binascii.hexlify(decrypted_plaintext).decode('utf-8')

# Example usage
plaintext = "User message to be encrypted"
ciphertext = encrypt_des(plaintext)
print("Ciphertext (encrypted):", ciphertext)
decrypted_plaintext = decrypt_des(ciphertext)
print("Decrypted plaintext (hexadecimal):", decrypted_plaintext)