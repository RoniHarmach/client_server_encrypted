import hashlib
import pickle
import secrets
import string
import random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Cryptodome.Cipher import AES
from pyDH import DiffieHellman
from hashlib import sha256


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

    @staticmethod
    def generate_rsa_keys():
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key

    @staticmethod
    def encrypt_rsa_message(public_rsa_key, message):
        public_key = RSA.import_key(public_rsa_key)
        cipher = PKCS1_OAEP.new(public_key)
        return cipher.encrypt(message)

    @staticmethod
    def generate_dh_keys():
        dh = DiffieHellman()

        private_key = dh.get_private_key()
        public_key = dh.gen_public_key()
        return private_key, public_key, dh

    @staticmethod
    def create_symmetric_key(key):
        return sha256(key.encode()).digest()

    @staticmethod
    def ds_aes_encrypt(dh_shared_key, data):
        symetric_key = Encryption.create_symmetric_key(dh_shared_key)
        return Encryption.aes_encrypt(symetric_key, data)

    @staticmethod
    def ds_aes_decrypt(dh_shared_key, iv, data):
        symmetric_key = Encryption.create_symmetric_key(dh_shared_key)
        return Encryption.aes_decrypt(symmetric_key, iv, data)

    @staticmethod
    def hash_password(password, salt, pepper):
        password_bytes = password.encode('utf-8')
        salt_bytes = salt.encode('utf-8')
        pepper_bytes = pepper.encode('utf-8')
        hashed_password = hashlib.sha256(password_bytes + salt_bytes + pepper_bytes).hexdigest()

        return hashed_password
