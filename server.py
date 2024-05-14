import socket
import threading
import datetime
import client_server_constants
from database import Database
from forgot_password_response import ForgotPasswordResponse
from login_response import LoginResponse
from protocol import Protocol
from protocol_codes import ProtocolCodes
from resend_verification_code_response import ResendVerificationCodeResponse
from sign_up_response import SignUpResponse
from sign_up_verification_request import SignUpVerificationRequest
from sign_up_verification_response import SignUpVerificationResponse
from user_data import UserData, Status
from verification_code import VerificationCode
from verification_code_creator import VerificationCodeCreator

all_to_die = False
database = Database()


def open_server_socket():
    srv_sock = socket.socket()
    srv_sock.bind((client_server_constants.SERVER_IP, client_server_constants.PORT))
    srv_sock.listen(2)
    srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    return srv_sock


def send_verification_email(user, email, verification_code):
    print(f"sent verification code '{verification_code} to {user} email {email}")


def check_login(user, password):
    user_data = database.get_user(user)
    if user_data is not None and user_data.password == password:
        return True
    return False


def is_valid_verification_code(request: SignUpVerificationRequest):
    verification = database.get_verification_code(request.user)
    if verification is None:
        print(f"missing verification code for user {request.user}")
        return False, "Invalid Verification Code"
    if verification.code != request.code:
        print(f"wrong verification code {request.code} sent by user {request.user}. Need to send code {verification.code}")
        return False, "Invalid Verification Code"
    if verification.expiration_time < datetime.datetime.now():
        print(f"verification code expired for user {request.user}")
        return False, "Expired Verification Code"

    return True, None

def handle_client(sock):
    global all_to_die
    finish = False
    while not finish:
        if all_to_die:
            print("will close due to main server issue")
            break
        code, message = Protocol.read_data(sock)
        if code == ProtocolCodes.LOGIN_REQUEST:
            if check_login(message.user, message.password):
                response = LoginResponse(result=True)
            else:
                response = LoginResponse(result=False, error=("user / password is incorrect"))
            Protocol.send_data(sock, ProtocolCodes.LOGIN_RESPONSE, response)
        elif code == ProtocolCodes.SIGN_UP_REQUEST:
            user_data = UserData(user=message.user, password=message.password, email=message.email, status=Status.WAITING_FOR_VERIFY)
            if database.create_user(user_data):
                verification_code = VerificationCodeCreator.create_code()
                current_datetime = datetime.datetime.now()
                expiration_time = current_datetime + datetime.timedelta(minutes=1)
                database.save_verification_code(message.user, VerificationCode(code=verification_code, expiration_time=expiration_time))
                send_verification_email(user_data.user, user_data.email, verification_code)
                response = SignUpResponse(result=True)
            else:
                response = SignUpResponse(result=False, error="User name already taken..")
            Protocol.send_data(sock, ProtocolCodes.SIGN_UP_RESPONSE, response)
        elif code == ProtocolCodes.FORGOT_PASSWORD_REQUEST:
            if message.user == "roni":
                response = ForgotPasswordResponse(result=True)
            else:
                response = ForgotPasswordResponse(result=False, error="User name already taken..")
            Protocol.send_data(sock, ProtocolCodes.FORGOT_PASSWORD_RESPONSE, response)
        elif code == ProtocolCodes.VERIFY_SIGN_UP_REQUEST:
            is_valid, error = is_valid_verification_code(message)
            if not is_valid:
                response = SignUpVerificationResponse(result=False, error=error)
            else:
                database.update_user_status(user=message.user, status=Status.VERIFIED)
                database.delete_verification_code(message.user)
                response = SignUpVerificationResponse(result=True)
            Protocol.send_data(sock, ProtocolCodes.VERIFY_SIGN_UP_RESPONSE, response)
        elif code == ProtocolCodes.RESEND_VERIFICATION_CODE_REQUEST:
            user_data = database.get_user(message.user)
            if user_data is None:
                response = ResendVerificationCodeResponse(result=False, error="Something went wrong")
            if user_data.status == Status.VERIFIED:
                response = ResendVerificationCodeResponse(result=False, error="User already finished the sign in process")
            else:
                verification_code = database.get_verification_code(user_data.user)
                if verification_code.expiration_time > datetime.datetime.now():
                    send_verification_email(verification_code=verification_code.code, user=user_data.user, email=user_data.email)
                    response = ResendVerificationCodeResponse(result=True)
                else:
                    # TODO - need to delete user and verification code from the database
                    response = ResendVerificationCodeResponse(result=False, error="Verification code expired. Please Sign Up again")
            Protocol.send_data(sock, ProtocolCodes.RESEND_VERIFICATION_CODE_RESPONSE, response)

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
