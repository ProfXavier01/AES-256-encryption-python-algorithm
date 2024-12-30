from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

def aes_encrypt (plain_text, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()

    padded_text = padder.update(plain_text.encode()) + padder.finalize()
    encrypted_text = encryptor.update(padded_text) + encryptor.finalize()
    return iv + encrypted_text

def aes_decrypt(encypted_data, key):
    iv = encrypted_data[:16]
    encrypted_text = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_text) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plain_text = unpadder.update(padded_data) + unpadder.finalize()
    return plain_text.decode()

if __name__ == "__main__":
    key = os.urandom(32) # 256 bits
    plain_text = input("Enter text to be encrypted:  " )
    print ('original_text', plain_text)
    encrypted_data = aes_encrypt (plain_text, key)
    print ("encrypted_data :", encrypted_data.hex())

    decrypted_data = aes_decrypt(encrypted_data, key)
    print ("decrypted_data: ", decrypted_data)