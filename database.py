import json
import threading
from dataclasses import dataclass
from typing import Dict
from user_data import UserData
from verification_code import VerificationCode


@dataclass
class Database:

    users: Dict[str, UserData]
    verification_codes = Dict[str, VerificationCode]
    reset_password_codes = Dict[str, VerificationCode]
    database_file_name = "./db/database.json"

    def __init__(self, users, verification_codes, reset_password_codes):
        self.lock = threading.Lock()
        self.users = users
        self.verification_codes = verification_codes
        self.reset_password_codes = reset_password_codes

    @classmethod
    def load_database(cls):
        try:
            with open(Database.database_file_name, 'r') as f:
                json_data = f.read()
            data = json.loads(json_data)
            return Database.from_json(data)
        except FileNotFoundError:
            return cls(users={}, verification_codes={}, reset_password_codes={})

    def save_database(self):
        with open(self.database_file_name, 'w') as f:
            json.dump(self.__json__(), f)

    @classmethod
    def from_json(cls, json):
        users = {key: UserData.from_json(user_data) for key, user_data in json['users'].items()}
        verification_codes = {key: VerificationCode.from_json(vc) for key, vc in json['verification_codes'].items()}
        reset_password_codes = {key: VerificationCode.from_json(rpc) for key, rpc in json['reset_password_codes'].items()}
        return cls(users=users, verification_codes=verification_codes, reset_password_codes=reset_password_codes)

    def __json__( self):
        serialized_user_data = {key: user_data.__json__() for key, user_data in self.users.items()}
        serialized_reset_password_codes = {key: reset_password_code.__json__() for key, reset_password_code in self.reset_password_codes.items()}
        serialized_verification_codes = {key: verification_code.__json__() for key, verification_code in self.verification_codes.items()}

        return {
            "users": serialized_user_data,
            "reset_password_codes": serialized_reset_password_codes,
            "verification_codes": serialized_verification_codes,
        }

    def create_user(self, user_data: UserData):
        with self.lock:
            if user_data.email in self.users:
                return False
            self.users[user_data.email] = user_data
            return True

    def get_user(self, email):
        return self.users.get(email)

    def save_verification_code(self, email, verification_code):
        self.verification_codes[email] = verification_code

    def save_reset_password_code(self, email, reset_password_code):
        self.reset_password_codes[email] = reset_password_code

    def get_verification_code(self, email):
        return self.verification_codes.get(email)

    def update_user_status(self, email, status):
        user_data = self.users.get(email)
        user_data.status = status

    def delete_verification_code(self, email):
        del self.verification_codes[email]

    def delete_user(self, email):
        del self.users[email]

    def delete_reset_code(self, email):
        del self.reset_password_codes[email]

    def is_password_ok(self, email, password):
        with self.lock:
            return self.users.get(email) == password

    def is_user_exist(self, email):
        with self.lock:
            return email in self.users

    def get_reset_code(self, email):
        return self.reset_password_codes.get(email)

    def update_password(self, email, password):
        user_data = self.get_user(email)
        user_data.password = password