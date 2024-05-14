from forgot_password_request import ForgotPasswordRequest
from login_request import LoginRequest
from protocol import Protocol
from protocol_codes import ProtocolCodes
from resend_verification_code_request import ResendVerificationCodeRequest
from reset_password_request import ResetPasswordRequest
from sign_up_request import SignUpRequest
from sign_up_verification_request import SignUpVerificationRequest


class UserLoginProtocol:
    client_server_protocol: Protocol = Protocol()
    sock: None

    def __init__(self, sock):
        self.sock = sock

    def login(self, email, password):
        message = LoginRequest(email=email, password=password)
        self.client_server_protocol.send_data(sock=self.sock, code=ProtocolCodes.LOGIN_REQUEST, message=message)
        code, message = self.client_server_protocol.read_data(sock=self.sock)
        if code != ProtocolCodes.LOGIN_RESPONSE:
            print("TODO: We need to check why")
        return message

    def sign_up(self, email, password):
        message = SignUpRequest(email=email, password=password)
        self.client_server_protocol.send_data(sock=self.sock, code=ProtocolCodes.SIGN_UP_REQUEST, message=message)
        code, message = self.client_server_protocol.read_data(sock=self.sock)
        if code != ProtocolCodes.SIGN_UP_RESPONSE:
            print("TODO: We need to check why")
        return message

    def verify_sign_up(self, email, verification_code):
        message = SignUpVerificationRequest(email=email, code=verification_code)
        self.client_server_protocol.send_data(sock=self.sock, code=ProtocolCodes.VERIFY_SIGN_UP_REQUEST, message=message)
        code, message = self.client_server_protocol.read_data(sock=self.sock)
        if code != ProtocolCodes.VERIFY_SIGN_UP_RESPONSE:
            print("TODO: We need to check why")
        return message

    def resend_sign_up_code(self, email):
        message = ResendVerificationCodeRequest(email)
        self.client_server_protocol.send_data(sock=self.sock, code=ProtocolCodes.RESEND_VERIFICATION_CODE_REQUEST, message=message)
        code, message = self.client_server_protocol.read_data(sock=self.sock)
        if code != ProtocolCodes.RESEND_VERIFICATION_CODE_RESPONSE:
            print("TODO: We need to check why")
        return message

    def forgot_password(self, email):
        message = ForgotPasswordRequest(email=email)
        self.client_server_protocol.send_data(sock=self.sock, code=ProtocolCodes.FORGOT_PASSWORD_REQUEST, message=message)
        code, message = self.client_server_protocol.read_data(sock=self.sock)
        if code != ProtocolCodes.FORGOT_PASSWORD_RESPONSE:
            print("TODO: We need to check why")
        return message

    def reset_password(self, email, password, reset_code):
        message = ResetPasswordRequest(email=email, password=password, reset_code=reset_code)
        self.client_server_protocol.send_data(sock=self.sock, code=ProtocolCodes.RESET_PASSWORD_REQUEST, message=message)
        code, message = self.client_server_protocol.read_data(sock=self.sock)
        if code != ProtocolCodes.RESET_PASSWORD_RESPONSE:
            print("TODO: We need to check why")
        return message
