from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import base64

def encrypt_cbc(key, plaintext):
    # Generate a random IV (Initialization Vector)
    iv = os.urandom(algorithms.AES.block_size // 8)

    # Pad the plaintext to be a multiple of the block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    # Create an AES cipher object with CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the padded data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Return the base64-encoded IV and ciphertext
    return base64.b64encode(iv + ciphertext)

def decrypt_cbc(key, ciphertext):
    # Decode the base64-encoded ciphertext
    ciphertext = base64.b64decode(ciphertext)

    # Extract the IV from the ciphertext
    iv = ciphertext[:algorithms.AES.block_size // 8]
    ciphertext = ciphertext[algorithms.AES.block_size // 8:]

    # Create an AES cipher object with CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(decrypted_data) + unpadder.finalize()

    return plaintext

# Example usage
key = b'Sixteen byte key'
plaintext = b'This is a sample plaintext.'

# Encrypt
encrypted_text = encrypt_cbc(key, plaintext)
print(f'Encrypted Text: {encrypted_text}')

# Decrypt
decrypted_text = decrypt_cbc(key, encrypted_text)
print(f'Decrypted Text: {decrypted_text.decode("utf-8")}')
