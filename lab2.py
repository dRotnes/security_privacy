from os import urandom
from binascii import hexlify
from cryptography.hazmat.primitives.ciphers import Cipher , algorithms , modes
from cryptography.hazmat.primitives import hashes

def crypto16bit():
    key = urandom(16)
    iv = urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()

    try:
        ct = encryptor.update(b"abcdefghijklmnop") + encryptor.finalize()
        print(hexlify(key))
        cphFile = open("ciphertext.bin","wb")
        cphFile .write(ct)
        cphFile .close ()
    except ValueError as err:
        print(err)

def cryptoCBC():
    key = urandom(32)
    iv = urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    
    try:
        ct = encryptor.update(b"abcdefghijklmnop") + encryptor.finalize()
        print('key:', hexlify(key).decode())
        print('iv:', hexlify(iv).decode())
        cphFile = open("ciphertextCBC.bin","wb")
        cphFile .write(ct)
        cphFile .close ()
    except ValueError as err:
        print(err)

def cryptoCTR():
    key = urandom(32)
    nonce = urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    
    try:
        ct = encryptor.update(b"abcdefghijklmnop") + encryptor.finalize()
        print('key:', hexlify(key).decode())
        print('nonce:', hexlify(nonce).decode())
        cphFile = open("ciphertextCTR.bin","wb")
        cphFile .write(ct)
        cphFile .close ()
    except ValueError as err:
        print(err)

def sha256():
    with open("2-Symmetric Cryptography + Hash Functions + MACs.pdf", "rb") as file:
        file_contents = file.read()
    
    digest = hashes.Hash(hashes.SHA256())

    digest.update(file_contents)

    print(digest.finalize().hex() == 'f8b14260a51b0405f29ff8bb2c765a0fe92aa6f6b34f3e0c0ec56452a81cd39e')

    #  as file:
    #     file_contents = file.read()
    # print(file_contents)

sha256()