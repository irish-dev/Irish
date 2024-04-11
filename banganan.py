def caesar_encrypt(plaintext, shift):
    encrypted = ""
    for char in plaintext:
        if char.isalpha():
            ascii_offset = ord('a') if char.islower() else ord('A')
            encrypted += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
        else:
            encrypted += char
    return encrypted

def caesar_decrypt(ciphertext, shift):
    return caesar_encrypt(ciphertext, -shift)

plaintext = "IRISH BANGANAN"
shift = 3

encrypted = caesar_encrypt(plaintext, shift)
print("Encrypted message:", encrypted)

decrypted = caesar_decrypt(encrypted, shift)
print("Decrypted message:", decrypted)