import pickle
import socket
import threading
import datetime
import client_server_constants
from database import Database
from encrypted_aes_message import EncryptedAESMessage
from encryption import Encryption
from forgot_password_response import ForgotPasswordResponse
from login_response import LoginResponse
from protocol import Protocol
from protocol_codes import ProtocolCodes
from resend_verification_code_response import ResendVerificationCodeResponse
from reset_password_request import ResetPasswordRequest
from reset_password_response import ResetPasswordResponse
from send_key_response import SendKeyResponse
from sign_up_response import SignUpResponse
from sign_up_verification_request import SignUpVerificationRequest
from sign_up_verification_response import SignUpVerificationResponse
from user_data import UserData, Status
from verification_code import VerificationCode
from random_code_creator import RandomCodeCreator

all_to_die = False
database = Database.load_database()
pepper = 'SKJNOmx'

def open_server_socket():
    srv_sock = socket.socket()
    srv_sock.bind((client_server_constants.SERVER_IP, client_server_constants.PORT))
    srv_sock.listen(2)
    srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    return srv_sock


def send_verification_email(email, verification_code):
    print(f"sent verification code '{verification_code} to email {email}")


def send_reset_password_email(email, reset_code):
    print(f"sent reset code '{reset_code} to email {email}")


def check_login(email, password):
    user_data = database.get_user(email)

    if user_data is None or user_data.status != Status.VERIFIED:
        return False

    salt = user_data.salt
    hashed_password = Encryption.hash_password(password=password, salt=salt, pepper=pepper)
    return user_data.password == hashed_password


def is_valid_verification_code(request: SignUpVerificationRequest):
    verification = database.get_verification_code(request.email)
    if verification is None:
        print(f"missing verification code for {request.email}")
        return False, "Invalid Verification Code", False
    if verification.code != str(request.code):
        print(f"wrong verification code {request.code} sent by user {request.email}. Need to send code {verification.code}")
        return False, "Invalid Verification Code2", verification.expiration_time < datetime.datetime.now()
    if verification.expiration_time < datetime.datetime.now():
        print(f"verification code expired for user {request.email}")
        return False, "Expired Verification Code", True

    return True, None, False


def is_valid_reset_code(request: ResetPasswordRequest):
    verification = database.get_reset_code(request.email)
    if verification is None:
        print(f"missing reset password code for {request.email}")
        return False, "Invalid Reset Password Code"
    if verification.code != str(request.reset_code):
        print(f"wrong reset code {request.reset_code} sent by user {request.email}. Need to send code {verification.code}")
        return False, "Invalid Reset Password Code"
    if verification.expiration_time < datetime.datetime.now():
        print(f"reset password code expired for user {request.email}")
        return False, "Expired Reset Password Code"

    return True, None


def get_future_datetime(added_minutes):
    current_datetime = datetime.datetime.now()
    return current_datetime + datetime.timedelta(minutes=added_minutes)


def is_user_expired(email):
    user_data = database.get_user(email)
    verification_code = database.get_verification_code(user_data.email)
    if user_data is not None and user_data.status is not Status.VERIFIED and verification_code.expiration_time < datetime.datetime.now():
        database.delete_user(user_data)
        return True
        # and database.get_verification_code(email=email)
    # return true if user exist AND user status != VERIFIED and it has expired verification code # delte_user, notifications
    return False

def wrap_with_encryption(key, message):
    iv, encrypted_message = Encryption.aes_encrypt(key, message)
    return EncryptedAESMessage(iv=iv, encrypted_message=encrypted_message)

def handle_client(sock):
    global all_to_die
    finish = False
    key = None

    while not finish:
        if all_to_die:
            print("will close due to main server issue")
            break
        code, request = Protocol.read_data(sock)
        if isinstance(request, EncryptedAESMessage):
            message = Encryption.aes_decrypt(key, request.iv, request.encrypted_message)
        else:
            message = request

        if code == ProtocolCodes.LOGIN_REQUEST:
            if check_login(message.email, message.password):
                response = LoginResponse(result=True)
            else:
                response = LoginResponse(result=False, error=("email / password is incorrect"))
            Protocol.send_data(sock, ProtocolCodes.LOGIN_RESPONSE, wrap_with_encryption(key, response))
        elif code == ProtocolCodes.SIGN_UP_REQUEST:
            ### TODO if trying to sign up existing email and user is not verified and verification code is expired:
            ### 1. delete existing user and expired verification code
            ### 2. allow sign up
            salt = Encryption.generate_salt()
            hashed_password = Encryption.hash_password(password=message.password, salt=salt, pepper=pepper)
            user_data = UserData(email=message.email, password=hashed_password, status=Status.WAITING_FOR_VERIFY, salt=salt)
            if database.create_user(user_data):
                verification_code = RandomCodeCreator.create_code()
                expiration_time = get_future_datetime(1)
                database.save_verification_code(message.email, VerificationCode(code=verification_code, expiration_time=expiration_time))
                database.save_database()
                send_verification_email(user_data.email, verification_code)
                response = SignUpResponse(result=True)
            else:
                if is_user_expired(message.email):
                    response = SignUpResponse(result=True)
                else:
                    response = SignUpResponse(result=False, error="User name already taken..")

            Protocol.send_data(sock, ProtocolCodes.SIGN_UP_RESPONSE, wrap_with_encryption(key, response))
        elif code == ProtocolCodes.FORGOT_PASSWORD_REQUEST:
            user_data = database.get_user(message.email)
            if user_data is not None and user_data.status == Status.VERIFIED:
                reset_password_code = RandomCodeCreator.create_code()
                expiration_time = get_future_datetime(5)
                database.save_reset_password_code(message.email, VerificationCode(code=reset_password_code, expiration_time=expiration_time))
                database.save_database()
                send_reset_password_email(user_data.email, reset_password_code)
            # Always return success because we don't want to tell if the email exist in the database
            response = ForgotPasswordResponse(result=True)
            Protocol.send_data(sock, ProtocolCodes.FORGOT_PASSWORD_RESPONSE, wrap_with_encryption(key, response))
        elif code == ProtocolCodes.VERIFY_SIGN_UP_REQUEST:
            is_valid, error, expired = is_valid_verification_code(message)
            if not is_valid:
                if expired:
                    print(f"deleting user {message.email}")
                    database.delete_verification_code(message.email)
                    database.delete_user(message.email)
                    database.save_database()
                response = SignUpVerificationResponse(result=False, error=error)
            else:
                database.update_user_status(email=message.email, status=Status.VERIFIED)
                database.delete_verification_code(message.email)
                database.save_database()
                response = SignUpVerificationResponse(result=True)

            Protocol.send_data(sock, ProtocolCodes.VERIFY_SIGN_UP_RESPONSE, wrap_with_encryption(key, response))
        elif code == ProtocolCodes.RESEND_VERIFICATION_CODE_REQUEST:
            user_data = database.get_user(message.email)
            if user_data is None:
                response = ResendVerificationCodeResponse(result=False, error="Something went wrong")
            elif user_data.status == Status.VERIFIED:
                response = ResendVerificationCodeResponse(result=False, error="User already finished the sign in process")
            else:
                verification_code = database.get_verification_code(user_data.email)

                if verification_code.expiration_time > datetime.datetime.now():
                    send_verification_email(verification_code=verification_code.code, email=user_data.email)
                    response = ResendVerificationCodeResponse(result=True)
                else:
                    database.delete_verification_code(user_data.email)
                    database.delete_user(user_data.email)
                    response = ResendVerificationCodeResponse(result=False, error="Verification code expired. Please Sign Up again")
            Protocol.send_data(sock, ProtocolCodes.RESEND_VERIFICATION_CODE_RESPONSE, wrap_with_encryption(key, response))
        elif code == ProtocolCodes.RESET_PASSWORD_REQUEST:
            is_valid, error = is_valid_reset_code(message)
            if not is_valid:
                response = ResetPasswordResponse(result=False, error=error)
            else:
                user_data = database.get_user(message.email)
                hashed_password = Encryption.hash_password(password=message.password, salt=user_data.salt,pepper=pepper)
                database.update_password(message.email, hashed_password)
                database.delete_reset_code(message.email)
                database.save_database()
                response = ResetPasswordResponse(result=True)
            Protocol.send_data(sock, ProtocolCodes.RESET_PASSWORD_RESPONSE, wrap_with_encryption(key, response))
        elif code == ProtocolCodes.SEND_SHARED_KEY_REQUEST:
            key = message.key
            response = SendKeyResponse(result=True)
            Protocol.send_data(sock, ProtocolCodes.SEND_SHARED_KEY_RESPONSE, response)


    sock.close()
    print("handle_client cloded")


def accept_clients(srv_sock):
    global all_to_die
    threads = []
    i = 1
    try:
        while True:
            print('\nMain thread: before accepting ...')
            cli_sock, addr = srv_sock.accept()  # accepts an incoming connection request from a TCP client.
            t = threading.Thread(target=handle_client, args=(cli_sock,))
            t.start()  # אומרת לתוכנית לפתוח את הטרד ולהריץ את ההנדל קליינט
            i += 1
            threads.append(t)
            if i > 100000000:  # for tests change it to 4
                print('\nMain thread: going down for maintenance')
                break
            ## מוסיפה למערך של הטרדים
    except socket.timeout:
        print("got timeout")
        all_to_die = True
    finally:

        print("waiting  for all clients to close")
        for t in threads:  #
            print("Joining thread " + t.getName())
            # לכל טרד
            t.join()  # עוצר את הטרייד מיין עד ש הטי סוגר את עצמו
        print("All Client threads ended")
        srv_sock.close()


def main():
    global all_to_die
    srv_sock = open_server_socket()
    accept_clients(srv_sock)


if __name__ == "__main__":
    main()
