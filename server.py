import socket
import sys
import threading
import datetime

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher.PKCS1_OAEP import PKCS1OAEP_Cipher
from Crypto.PublicKey import RSA
from rsa import DecryptionError

import client_server_constants
from database import Database
from dh_pub_key_response import DhPubKeyResponse
from email_sender import EmailSender
from encrypted_aes_message import EncryptedAESMessage
from encryption import Encryption
from encryption_support_check_response import EncryptionSupportCheckResponse
from encryption_type import EncryptionType
from forgot_password_response import ForgotPasswordResponse
from rsa_public_key_response import RsaPublicKeyResponse
from login_response import LoginResponse
from protocol import Protocol
from protocol_codes import ProtocolCodes
from resend_verification_code_response import ResendVerificationCodeResponse
from reset_password_request import ResetPasswordRequest
from reset_password_response import ResetPasswordResponse
from aes_key_exchange_response import AesKeyExchangeResponse
from sign_up_response import SignUpResponse
from sign_up_verification_request import SignUpVerificationRequest
from sign_up_verification_response import SignUpVerificationResponse
from user_data import UserData, Status
from verification_code import VerificationCode
from random_code_creator import RandomCodeCreator
all_to_die = False
database = Database.load_database()
pepper = 'SKJNOmx'
private_rsa_key = None
public_rsa_key = None
cipher: PKCS1OAEP_Cipher = None


def open_server_socket():
    srv_sock = socket.socket()
    srv_sock.bind((client_server_constants.SERVER_IP, client_server_constants.PORT))
    srv_sock.listen(2)
    srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    return srv_sock


def send_verification_email(email, code):
    email_sender.send_email(email, "Sign up verification code", f"Your recovery code for reset password is {code}")


def send_reset_password_email(email, reset_code):
    email_sender.send_email(email, "Reset password code", f"Your recovery code for reset password is {reset_code}")


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


def handle_login_request(message):
    if check_login(message.email, message.password):
        response = LoginResponse(result=True)
    else:
        response = LoginResponse(result=False, error=("email / password is incorrect"))
    return response, ProtocolCodes.LOGIN_RESPONSE, True


def handle_sign_up_request(message):
    salt = Encryption.generate_salt()
    hashed_password = Encryption.hash_password(password=message.password, salt=salt, pepper=pepper)
    user_data = UserData(email=message.email, password=hashed_password, status=Status.WAITING_FOR_VERIFY, salt=salt)
    if database.create_user(user_data):
        verification_code = RandomCodeCreator.create_code()
        expiration_time = get_future_datetime(1)
        database.save_verification_code(message.email,
                                        VerificationCode(code=verification_code, expiration_time=expiration_time))
        database.save_database()
        send_verification_email(user_data.email, verification_code)
        response = SignUpResponse(result=True)
    else:
        if is_user_expired(message.email):
            response = SignUpResponse(result=True)
        else:
            response = SignUpResponse(result=False, error="User name already taken..")
    return response, ProtocolCodes.SIGN_UP_RESPONSE, True


def handle_forgot_password_request(message):
    user_data = database.get_user(message.email)
    if user_data is not None and user_data.status == Status.VERIFIED:
        reset_password_code = RandomCodeCreator.create_code()
        expiration_time = get_future_datetime(5)
        database.save_reset_password_code(message.email,
                                          VerificationCode(code=reset_password_code, expiration_time=expiration_time))
        database.save_database()
        send_reset_password_email(user_data.email, reset_password_code)
    # Always return success because we don't want to tell if the email exist in the database
    return ForgotPasswordResponse(result=True), ProtocolCodes.FORGOT_PASSWORD_RESPONSE, True


def handle_verify_sign_up_request(message):
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
        response =  SignUpVerificationResponse(result=True)
    return response, ProtocolCodes.VERIFY_SIGN_UP_RESPONSE, True


def handle_resend_verification_code(message):
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
    return response, ProtocolCodes.RESEND_VERIFICATION_CODE_RESPONSE, True


def handle_reset_password_request(message):
    is_valid, error = is_valid_reset_code(message)
    if not is_valid:
        response = ResetPasswordResponse(result=False, error=error)
    else:
        user_data = database.get_user(message.email)
        hashed_password = Encryption.hash_password(password=message.password, salt=user_data.salt, pepper=pepper)
        database.update_password(message.email, hashed_password)
        database.delete_reset_code(message.email)
        database.save_database()
        response = ResetPasswordResponse(result=True)
    return response, ProtocolCodes.RESET_PASSWORD_RESPONSE, True


def handle_check_encryption_support_request(message):
    if message.encryption_type in [EncryptionType.RSA, EncryptionType.DIFFIE_HELLMAN]:
        response = EncryptionSupportCheckResponse(encryption_supported=True)
    else:
        response = EncryptionSupportCheckResponse(encryption_supported=False,
                                                  error=f"The server does not support {message.encryption_type}")
    return response, ProtocolCodes.CHECK_ENCRYPTION_SUPPORT_RESPONSE, False


def handle_rsa_public_key_request():
    global public_rsa_key
    response = RsaPublicKeyResponse(rsa_public_key=public_rsa_key)
    return response, ProtocolCodes.RSA_PUBLIC_KEY_RESPONSE, False


def handle_rsa_aes_key_exchange_request(message):
    key: None
    try:
        encrypted_key_with_rsa = message.key
        key = cipher.decrypt(encrypted_key_with_rsa)
        response = AesKeyExchangeResponse(result=True)
    except (ValueError, DecryptionError) as e:
        response = AesKeyExchangeResponse(result=False, error="Failed to decrypt message")
    return key, response, ProtocolCodes.AES_KEY_EXCHANGE_RESPONSE, False


def handle_dh_public_key_request(message):
    server_private_key, server_public_key, dh = Encryption.generate_dh_keys()
    shared_key = dh.gen_shared_key(message.client_public_key)
    response = DhPubKeyResponse(server_public_key=server_public_key, result=True)
    return dh, shared_key, response, ProtocolCodes.DH_CLIENT_PUB_KEY_RESPONSE, False


def handle_dh_aes_key_exchange_request(message, dh_shared_key):
    decrypted_aes_key: None
    try:
        encrypted_key_with_dh = message.key
        iv = message.iv

        decrypted_aes_key = Encryption.ds_aes_decrypt(dh_shared_key=dh_shared_key, iv=iv, data=encrypted_key_with_dh)
        response = AesKeyExchangeResponse(result=True)
    except (ValueError, DecryptionError) as e:
        response = AesKeyExchangeResponse(result=False, error="Failed to decrypt message")
    return decrypted_aes_key, response, ProtocolCodes.AES_KEY_EXCHANGE_RESPONSE, False


def handle_client(sock):
    global all_to_die
    finish = False
    client_aes_key = None
    encrypt_response = False
    response_code = None
    dh: None
    dh_shared_key: None

    while not finish:
        if all_to_die:
            print("will close due to main server issue")
            break
        code, request = Protocol.read_data(sock)
        if isinstance(request, EncryptedAESMessage):
            message = Encryption.aes_decrypt(client_aes_key, request.iv, request.encrypted_message)
        else:
            message = request

        if code == ProtocolCodes.LOGIN_REQUEST:
            response, response_code, encrypt_response = handle_login_request(message)
        elif code == ProtocolCodes.SIGN_UP_REQUEST:
            response, response_code, encrypt_response = handle_sign_up_request(message)
        elif code == ProtocolCodes.FORGOT_PASSWORD_REQUEST:
            response, response_code, encrypt_response = handle_forgot_password_request(message)
        elif code == ProtocolCodes.VERIFY_SIGN_UP_REQUEST:
            response, response_code, encrypt_response = handle_verify_sign_up_request(message)
        elif code == ProtocolCodes.RESEND_VERIFICATION_CODE_REQUEST:
            response, response_code, encrypt_response = handle_resend_verification_code(message)
        elif code == ProtocolCodes.RESET_PASSWORD_REQUEST:
            response, response_code, encrypt_response = handle_reset_password_request(message)
        elif code == ProtocolCodes.RSA_AES_KEY_EXCHANGE_REQUEST:
            client_aes_key, response, response_code, encrypt_response = handle_rsa_aes_key_exchange_request(message)
        elif code == ProtocolCodes.CHECK_ENCRYPTION_SUPPORT_REQUEST:
            response, response_code, encrypt_response = handle_check_encryption_support_request(message)
        elif code == ProtocolCodes.RSA_PUBLIC_KEY_REQUEST:
            response, response_code, encrypt_response = handle_rsa_public_key_request()
        elif code == ProtocolCodes.DH_CLIENT_PUB_KEY_REQUEST:
            dh, dh_shared_key, response, response_code, encrypt_response = handle_dh_public_key_request(message)
        elif code == ProtocolCodes.DH_AES_KEY_EXCHANGE_REQUEST:
            client_aes_key, response, response_code, encrypt_response = handle_dh_aes_key_exchange_request(message, dh_shared_key)
            # TODO handle unknown code(add UNSUPPORTED_CODE_RESPONSE)

        response_message = wrap_with_encryption(client_aes_key, response) if encrypt_response else response

        Protocol.send_data(sock, response_code, response_message)
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


def create_rsa_keys():
    global all_to_die, private_rsa_key, public_rsa_key, cipher
    private_rsa_key, public_rsa_key = Encryption.generate_rsa_keys()
    private_key = RSA.import_key(private_rsa_key)
    cipher = PKCS1_OAEP.new(private_key)


def create_email_sender(email, password):
    global email_sender
    email_sender = EmailSender(email, password)


def main(email, password):
    global all_to_die
    create_rsa_keys()
    create_email_sender(email, password)
    srv_sock = open_server_socket()
    accept_clients(srv_sock)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
