from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import base64

def encrypt_ofb(key, plaintext):
    # Generate a random IV (Initialization Vector)
    iv = os.urandom(algorithms.AES.block_size // 8)

    # Create an AES cipher object with OFB mode
    cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the plaintext
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Return the base64-encoded IV and ciphertext
    return base64.b64encode(iv + ciphertext)

def decrypt_ofb(key, ciphertext):
    # Decode the base64-encoded ciphertext
    ciphertext = base64.b64decode(ciphertext)

    # Extract the IV from the ciphertext
    iv = ciphertext[:algorithms.AES.block_size // 8]
    ciphertext = ciphertext[algorithms.AES.block_size // 8:]

    # Create an AES cipher object with OFB mode
    cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    return decrypted_data

# Example usage
key = b'Sixteen byte key'
plaintext = b'This is a sample plaintext.'

# Encrypt
encrypted_text = encrypt_ofb(key, plaintext)
print(f'Encrypted Text: {encrypted_text}')

# Decrypt
decrypted_text = decrypt_ofb(key, encrypted_text)
print(f'Decrypted Text: {decrypted_text.decode("utf-8")}')
