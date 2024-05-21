from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import tkinter as tk
import socket
import threading
import pickle
import hashlib
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
import string
from datetime import datetime, timedelta
from Crypto.PublicKey import RSA
from Crypto.Util import number
from Crypto.Util.Padding import pad

class Server:


    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.pepper = self.load_pepper()
        self.users = self.load_user_data()
        self.email_codes = {}
        self.key = None

    def encrypt_message(self, message, key):
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(message.encode())
        return ct_bytes, cipher.iv


    def decrypt_message(self, ct_bytes, key, iv):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = cipher.decrypt(ct_bytes).decode()
        return pt.rstrip('\0')


    def load_user_data(self):
        try:
            with open('users.pickle', 'rb') as file:
                return pickle.load(file)
        except FileNotFoundError:
            return {}

    def save_user_data(self):
        with open('users.pickle', 'wb') as file:
            pickle.dump(self.users, file)

    def load_pepper(self):
        try:
            with open('pepper.txt', 'r') as file:
                return file.read()
        except FileNotFoundError:
            return os.urandom(16).hex()

    def handle_client(self, conn, addr):
        while True:
            try:
                data = conn.recv(1024)
                if not data:
                    break

                if self.key is None:
                    conn.send(pickle.dumps({'status': 'ERROR', 'message': 'Encryption key not received.'}))
                    continue

                decrypted_data = self.decrypt_message(data)
                request = pickle.loads(decrypted_data)
                command = request['command']

                if command == 'SELECT_KEY_EXCHANGE_METHOD':
                    key_exchange_method = request['key_exchange_method']
                    if key_exchange_method == 'RSA':
                        rsa_public_key = RSA.generate(2048).publickey().export_key()
                        conn.send(rsa_public_key)
                        client_rsa_public_key = RSA.import_key(conn.recv(4096))
                    elif key_exchange_method == 'Diffie-Hellman':
                        dh_params = DH.generate(2048)
                        dh_private_key = dh_params.private_key
                        dh_public_key = dh_params.public_key()
                        conn.send(dh_public_key.to_bytes())
                        client_public_key = DHPublicKey.from_bytes(conn.recv(4096))
                        shared_secret = dh_private_key.exchange(client_public_key)
                        aes_key = hashlib.sha256(shared_secret).digest()
                        self.key = aes_key

                    else:
                        conn.send(pickle.dumps({'status': 'ERROR', 'message': 'Chosen key exchange method is not supported'}))
                    continue

                if command == 'REGISTER':
                    username = request['username']
                    password = request['password']
                    email = request['email']
                    if email in self.email_codes and (
                            datetime.now() - self.email_codes[email]['timestamp']).seconds < 300:
                        response = {'status': 'ERROR', 'message': 'Code already sent. Please check your email.'}
                    else:
                        code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
                        self.email_codes[email] = {'code': code, 'timestamp': datetime.now()}
                        self.send_email(email, code)
                        response = {'status': 'CODE_SENT',
                                    'message': 'Verification code sent. Please check your email.'}
                elif command == 'VERIFY_CODE':
                    username = request['username']
                    password = request['password']
                    email = request['email']
                    code = request['code']
                    if email not in self.email_codes or (
                            datetime.now() - self.email_codes[email]['timestamp']).seconds > 300 or \
                            self.email_codes[email]['code'] != code:
                        response = {'status': 'ERROR', 'message': 'Invalid verification code'}
                    else:
                        del self.email_codes[email]
                        salt = os.urandom(16).hex()
                        hashed_password = hashlib.sha256((password + salt + self.pepper).encode()).hexdigest()
                        if username in self.users:
                            response = {'status': 'ERROR', 'message': 'User already exists'}
                        else:
                            self.users[username] = {'password': hashed_password, 'salt': salt, 'email': email}
                            self.save_user_data()
                            response = {'status': 'OK', 'message': 'User registered successfully'}
                elif command == 'LOGIN':
                    username = request['username']
                    password = request['password']
                    if username not in self.users:
                        response = {'status': 'ERROR', 'message': 'Invalid username or password'}
                    else:
                        stored_password = self.users[username]['password']
                        salt = self.users[username]['salt']
                        hashed_password = hashlib.sha256((password + salt + self.pepper).encode()).hexdigest()
                        if stored_password != hashed_password:
                            response = {'status': 'ERROR', 'message': 'Invalid username or password'}
                        else:
                            response = {'status': 'OK', 'message': 'Login successful'}
                elif command == 'RECOVER_PASSWORD':
                    email = request['email']
                    if email not in self.users:
                        response = {'status': 'ERROR', 'message': 'Email not registered'}
                    else:
                        code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
                        self.email_codes[email] = {'code': code, 'timestamp': datetime.now()}
                        self.send_email(email, code)
                        response = {'status': 'CODE_SENT',
                                    'message': 'Password recovery code sent. Please check your email.'}
                elif command == 'VERIFY_PASSWORD_RECOVERY_CODE':
                    email = request['email']
                    code = request['code']
                    if email not in self.email_codes or (
                            datetime.now() - self.email_codes[email]['timestamp']).seconds > 300 or \
                            self.email_codes[email]['code'] != code:
                        response = {'status': 'ERROR', 'message': 'Invalid recovery code'}
                    else:
                        del self.email_codes[email]
                        response = {'status': 'OK', 'message': 'Verification code accepted'}

                encrypted_response = self.encrypt_message(pickle.dumps(response))
                conn.send(pickle.dumps(encrypted_response))

            except Exception as e:
                print(f"Error processing request from {addr}: {e}")
                break

        conn.close()

    def send_email(self, email, code):
        sender_email = "your-email@gmail.com"
        password = "your-email-password"
        message = MIMEMultipart()
        message['From'] = sender_email
        message['To'] = email
        message['Subject'] = "Verification Code"

        body = f"Your verification code is: {code}"
        message.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, password)
        server.sendmail(sender_email, email, message.as_string())
        server.quit()

    def start_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        while True:
            conn, addr = server_socket.accept()
            threading.Thread(target=self.handle_client, args=(conn, addr)).start()


class ClientGUI:

    def encrypt_message(self, message, key):
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(message.encode())
        return ct_bytes, cipher.iv


    def decrypt_message(self, ct_bytes, key, iv):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = cipher.decrypt(ct_bytes).decode()
        return pt.rstrip('\0')


    def __init__(self, master):
        self.master = master
        self.master.title("User Authentication")
        self.master.geometry("300x200")

        self.label_username = tk.Label(master, text="Username:")
        self.label_username.grid(row=0, column=0, sticky="w")
        self.entry_username = tk.Entry(master)
        self.entry_username.grid(row=0, column=1)

        self.label_password = tk.Label(master, text="Password:")
        self.label_password.grid(row=1, column=0, sticky="w")
        self.entry_password = tk.Entry(master, show="*")
        self.entry_password.grid(row=1, column=1)

        self.label_email = tk.Label(master, text="Email:")
        self.label_email.grid(row=2, column=0, sticky="w")
        self.entry_email = tk.Entry(master)
        self.entry_email.grid(row=2, column=1)

        self.button_login = tk.Button(master, text="Login", command=self.login)
        self.button_login.grid(row=3, column=0, pady=5)
        self.button_register = tk.Button(master, text="Register", command=self.register)
        self.button_register.grid(row=3, column=1, pady=5)
        self.button_forgot_password = tk.Button(master, text="Forgot Password", command=self.forgot_password)
        self.button_forgot_password.grid(row=4, columnspan=2, pady=5)

        self.status_label = tk.Label(master, text="", fg="red")
        self.status_label.grid(row=5, columnspan=2)

        self.selected_key_exchange_method = tk.StringVar()
        self.radio_button_rsa = tk.Radiobutton(master, text="RSA", variable=self.selected_key_exchange_method, value="RSA")
        self.radio_button_rsa.grid(row=5, column=0)
        self.radio_button_dh = tk.Radiobutton(master, text="Diffie-Hellman", variable=self.selected_key_exchange_method, value="Diffie-Hellman")
        self.radio_button_dh.grid(row=5, column=1)

    def login(self):
        username = self.entry_username.get()
        password = self.entry_password.get()
        self.send_request({'command': 'LOGIN', 'username': username, 'password': password})

    def register(self):
        username = self.entry_username.get()
        password = self.entry_password.get()
        email = self.entry_email.get()
        self.send_request({'command': 'REGISTER', 'username': username, 'password': password, 'email': email})

    def forgot_password(self):
        email = self.entry_email.get()
        self.send_request({'command': 'RECOVER_PASSWORD', 'email': email})

    def send_request(self, request):
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect(('127.0.0.1', 5555))
            client_socket.send(pickle.dumps(request))

            response = pickle.loads(client_socket.recv(1024))
            if response['status'] == 'ERROR':
                print(response['message'])
                return

            if response['key_exchange'] == 'RSA':
                public_key = self.generate_rsa_key()
                client_socket.send(pickle.dumps(public_key))
                server_public_key = pickle.loads(client_socket.recv(1024))
                aes_key = self.generate_aes_key()
                encrypted_aes_key = self.encrypt_rsa(aes_key, server_public_key)
                client_socket.send(pickle.dumps(encrypted_aes_key))

            elif response['key_exchange'] == 'DH':
                base, prime = self.generate_dh_parameters()
                client_socket.send(pickle.dumps((base, prime)))
                server_base, server_prime = pickle.loads(client_socket.recv(1024))
                shared_secret = self.calculate_dh_shared_secret(base, prime, server_base, server_prime)
                aes_key = self.generate_aes_key_from_shared_secret(shared_secret)
                client_socket.send(pickle.dumps(aes_key))

            encrypted_response = client_socket.recv(1024)
            response = self.decrypt_aes(encrypted_response, aes_key)
            self.status_label.config(text=response['message'], fg="green" if response['status'] == 'OK' else "red")

        except Exception as e:
            print(f"Error: {e}")
        finally:
            client_socket.close()


def main():
    server = Server('127.0.0.1', 5555)
    server_thread = threading.Thread(target=server.start_server)
    server_thread.daemon = True
    server_thread.start()

    root = tk.Tk()
    client_gui = ClientGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
