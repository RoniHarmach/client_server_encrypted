import threading

from user_data import UserData, Status
import datetime

from verification_code import VerificationCode


class Database:
    users = {
            "roni": UserData(user="roni", password="blondie", email="ronron.harmach@gmail.com", status=Status.VERIFIED),
            "omer": UserData(user="omer", password="qute", email="omer.harmach@gmail.com", status=Status.WAITING_FOR_VERIFY)
        }

    verification_codes = {"omer": VerificationCode(code="654321", expiration_time=datetime.datetime.now())}

    def __init__(self):
        self.lock = threading.Lock()

    def create_user(self, user_data: UserData):
        with self.lock:
            if user_data.user in self.users:
                return False
            self.users[user_data.user] = user_data
            return True

    def get_user(self, user):
        return self.users.get(user)

    def save_verification_code(self, user, verification_code):
        self.verification_codes[user] = verification_code

    def get_verification_code(self, user):
        return self.verification_codes[user]

    def update_user_status(self, user, status):
        user_data = self.users.get(user)
        user_data.status = status

    def delete_verification_code(self, user):
        del self.verification_codes[user]

    def is_password_ok(self, username, password):
        with self.lock:
            return self.users.get(username) == password

    def is_user_exist(self, username):
        with self.lock:
            return username in self.users
