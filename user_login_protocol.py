from forgot_password_request import ForgotPasswordRequest
from login_request import LoginRequest
from login_response import LoginResponse
from protocol import Protocol
from protocol_codes import ProtocolCodes
from sign_up_request import SignUpRequest
from sign_up_verification_request import SignUpVerificationRequest


class UserLoginProtocol:
    client_server_protocol: Protocol = Protocol()
    sock: None

    def __init__(self, sock):
        self.sock = sock

    def login(self, user, password):
        message = LoginRequest(user=user, password=password)
        self.client_server_protocol.send_data(sock=self.sock, code=ProtocolCodes.LOGIN_REQUEST, message=message)
        code, message = self.client_server_protocol.read_data(sock=self.sock)
        if code != ProtocolCodes.LOGIN_RESPONSE:
            print("TODO: We need to check why")
        return message

    def sign_up(self, user, email, password):
        message = SignUpRequest(user=user, email=email, password=password)
        self.client_server_protocol.send_data(sock=self.sock, code=ProtocolCodes.SIGN_UP_REQUEST, message=message)
        code, message = self.client_server_protocol.read_data(sock=self.sock)
        if code != ProtocolCodes.SIGN_UP_RESPONSE:
            print("TODO: We need to check why")
        return message

    def verify_sign_up(self, user, verification_code):
        message = SignUpVerificationRequest(user=user, code=verification_code)
        self.client_server_protocol.send_data(sock=self.sock, code=ProtocolCodes.VERIFY_SIGN_UP_REQUEST, message=message)
        code, message = self.client_server_protocol.read_data(sock=self.sock)
        if code != ProtocolCodes.VERIFY_SIGN_UP_RESPONSE:
            print("TODO: We need to check why")
        return message

    def forgot_password(self, user):
        message = ForgotPasswordRequest(user=user)
        self.client_server_protocol.send_data(sock=self.sock, code=ProtocolCodes.FORGOT_PASSWORD_REQUEST, message=message)
        code, message = self.client_server_protocol.read_data(sock=self.sock)
        if code != ProtocolCodes.FORGOT_PASSWORD_RESPONSE:
            print("TODO: We need to check why")
        return message

    def reset_password(self, user, password, reset_code):
        pass

    def verify_reset_code(self, user, reset_code):
        pass