import threading

class Database:
    def __init__(self):
        self.lock = threading.Lock()
        self.users = {}

    def save_user(self, username, password):
        with self.lock:
            if username in self.users:
                return False  # User already exists
            else:
                self.users[username] = password
                return True

    def is_password_ok(self, username, password):
        with self.lock:
            return self.users.get(username) == password

    def is_user_exist(self, username):
        with self.lock:
            return username in self.users
