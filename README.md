from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Encryption function
def encrypt_message(message, key):
    iv = os.urandom(16)  # Generate a random initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
    return iv + encrypted_message  # Return IV concatenated with encrypted message

# Decryption function
def decrypt_message(encrypted_message, key):
    iv = encrypted_message[:16]  # Extract IV from the start
    cipher_text = encrypted_message[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(cipher_text) + decryptor.finalize()
    return decrypted_message.decode()

# Example usage
key = os.urandom(32)  # AES key (256 bits)
message = "Transfer $100 to account 12345"

encrypted_message = encrypt_message(message, key)
print(f"Encrypted: {encrypted_message}")
decrypted_message = decrypt_message(encrypted_message, key)
print(f"Decrypted: {decrypted_message}")
