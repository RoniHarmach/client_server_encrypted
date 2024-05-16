import hashlib
import pickle
import secrets
import string
from dataclasses import dataclass
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Cryptodome.Cipher import AES


class Encryption:

    @staticmethod
    def generate_key():
        return bytes(random.randint(0, 255) for _ in range(16))

    @staticmethod
    def aes_encrypt(key, data):
        data_bytes = pickle.dumps(data)
        cipher = AES.new(key, AES.MODE_CBC)
        iv = cipher.iv
        ciphertext = cipher.encrypt(pad(data_bytes, AES.block_size))
        return iv, ciphertext

    @staticmethod
    def aes_decrypt(key, iv, data):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        data_bytes = unpad(cipher.decrypt(data), AES.block_size)
        return pickle.loads(data_bytes)

    @staticmethod
    def generate_salt(length=16):
        # Generate a random salt of the specified length
        salt_characters = string.ascii_letters + string.digits + string.punctuation
        salt = ''.join(secrets.choice(salt_characters) for _ in range(length))
        return salt

    def hash_password(password, salt, pepper):
        password_bytes = password.encode('utf-8')
        salt_bytes = salt.encode('utf-8')
        pepper_bytes = pepper.encode('utf-8')
        hashed_password = hashlib.sha256(password_bytes + salt_bytes + pepper_bytes).hexdigest()

        return hashed_password


