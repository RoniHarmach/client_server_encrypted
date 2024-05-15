import hashlib
import secrets
import string
from dataclasses import dataclass
from hashlib import sha256


class Encryption:

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

@dataclass
class EncryptionData:
    salt = Encryption.generate_salt()




