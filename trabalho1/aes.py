import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import time

def aes_main():
    encoded_data = get_encoded_data()
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    
    start_encrypt = time.time()
    crypted_msg = aes_encrypt(encoded_data, nonce, aesgcm)
    end_encrypt = time.time()
    
    start_decrypt = time.time()
    decrypted_msg = aes_decrypt(crypted_msg, nonce, aesgcm)
    end_decrypt = time.time()
    
    
    encrypt_time = end_encrypt - start_encrypt
    decrypt_time = end_decrypt - start_decrypt
    total_time = end_decrypt - start_encrypt
    print(f"Encrypt time: {encrypt_time} secs\nDecrypt time: {decrypt_time} secs\nTotal time: {total_time}")


def get_encoded_data() -> bytes:
    file = open("byte8.txt", "r")
    message = file.read()
    encoded_data = message.encode("utf-8")
    return encoded_data

def aes_encrypt(message: bytes, nonce: bytes, aesgcm) -> bytes:
    return aesgcm.encrypt(nonce, message, None)

def aes_decrypt(message: bytes, nonce: bytes, aesgcm) -> str:
    return aesgcm.decrypt(nonce, message, None)

aes_main()