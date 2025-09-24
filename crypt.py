from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import sys
import argparse
import base64

parser = argparse.ArgumentParser(description="Encrypt or decrypt files using AES and cripto")
parser.add_argument("filepath", help="Path to the file to be processed")
parser.add_argument("crypto_type", choices=["cripto", "AES"], help="Type of cryptography to use")

key = os.urandom(32)  # 256-bit key (use 16 for AES-128, 24 for AES-192)
iv = os.urandom(16)   # 128-bit IV for AES

args = parser.parse_args()

print(f"Filepath: {args.filepath}, Crypto Type: {args.crypto_type}")

with open(args.filepath, 'rb') as file: plaintext = file.read()


if args.crypto_type == "AES":
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    # --- Encrypt ---
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    ciphertext_b64 = base64.b64encode(ciphertext).decode("utf-8")
    with open("encrypted_aes.bin", 'w') as enc_file: enc_file.write(ciphertext_b64)

    # --- Decrypt ---
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

    # --- Remove padding ---
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()

    decrypted_data = decrypted_data.decode("utf-8")
    with open("decrypted_aes.bin", 'w') as dec_file: dec_file.write(decrypted_data)


