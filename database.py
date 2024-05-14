import threading

from user_data import UserData, Status
import datetime

from verification_code import VerificationCode


class Database:
    users = {
            "ronron.harmach@gmail.com": UserData(password="blondie", email="ronron.harmach@gmail.com", status=Status.VERIFIED),
            "omer.harmach@gmail.com": UserData(password="qute", email="omer.harmach@gmail.com", status=Status.WAITING_FOR_VERIFY)
        }

    verification_codes = {"omer.harmach@gmail.com": VerificationCode(code="654321", expiration_time=datetime.datetime.now())}

    def __init__(self):
        self.lock = threading.Lock()

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

    def get_verification_code(self, email):
        return self.verification_codes[email]

    def update_user_status(self, email, status):
        user_data = self.users.get(email)
        user_data.status = status

    def delete_verification_code(self, email):
        del self.verification_codes[email]

    def is_password_ok(self, email, password):
        with self.lock:
            return self.users.get(email) == password

    def is_user_exist(self, email):
        with self.lock:
            return email in self.users
