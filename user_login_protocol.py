
from encrypted_aes_message import EncryptedAESMessage
from encryption import Encryption
from forgot_password_request import ForgotPasswordRequest
from login_request import LoginRequest
from protocol import Protocol
from protocol_codes import ProtocolCodes
from resend_verification_code_request import ResendVerificationCodeRequest
from reset_password_request import ResetPasswordRequest
from send_key_request import SendKeyRequest
from sign_up_request import SignUpRequest
from sign_up_verification_request import SignUpVerificationRequest


class UserLoginProtocol:
    client_server_protocol: Protocol = Protocol()
    sock =  None
    key = None

    def __init__(self, sock):
        self.sock = sock

    def generate_key(self):
        self.key = Encryption.generate_key()

    def send_key(self):
        message = SendKeyRequest(self.key)
        self.client_server_protocol.send_data(sock=self.sock, code=ProtocolCodes.SEND_SHARED_KEY_REQUEST,
                                              message=message)
        code, message = self.client_server_protocol.read_data(self.sock)
        if code != ProtocolCodes.SEND_SHARED_KEY_RESPONSE:
            print("TODO: We need to check why")
        return message

    def encrypted_message(self, message):
        if self.key is None:
            self.generate_key()
            self.send_key()
        iv, encrypted_message = Encryption.aes_encrypt(self.key, message)
        return iv, encrypted_message

    def decrypt_message(self, message):
        decrypted_message = Encryption.aes_decrypt(key=self.key, iv=message.iv, data=message.encrypted_message)
        return decrypted_message

    def wrap_with_encryption(self, message):
        iv, encrypted_request = self.encrypted_message(message)
        return EncryptedAESMessage(iv=iv, encrypted_message=encrypted_request)

    def login(self, email, password):
        login_message = LoginRequest(email=email, password=password)
        encrypted_message = self.wrap_with_encryption(login_message)
        self.client_server_protocol.send_data(sock=self.sock, code=ProtocolCodes.LOGIN_REQUEST, message=encrypted_message)
        code, encrypted_response = self.client_server_protocol.read_data(sock=self.sock)
        decrypted_response = self.decrypt_message(encrypted_response)
        if code != ProtocolCodes.LOGIN_RESPONSE:
            print("TODO: We need to check why")
        return decrypted_response

    def sign_up(self, email, password):
        sign_up_message = SignUpRequest(email=email, password=password)
        encrypted_message = self.wrap_with_encryption(sign_up_message)
        self.client_server_protocol.send_data(sock=self.sock, code=ProtocolCodes.SIGN_UP_REQUEST, message=encrypted_message)
        code, encrypted_response = self.client_server_protocol.read_data(sock=self.sock)
        decrypted_response = self.decrypt_message(encrypted_response)

        if code != ProtocolCodes.SIGN_UP_RESPONSE:
            print("TODO: We need to check why")
        return decrypted_response

    def verify_sign_up(self, email, verification_code):
        verify_message = SignUpVerificationRequest(email=email, code=verification_code)
        encrypted_message = self.wrap_with_encryption(verify_message)

        self.client_server_protocol.send_data(sock=self.sock, code=ProtocolCodes.VERIFY_SIGN_UP_REQUEST, message=encrypted_message)

        code, encrypted_response = self.client_server_protocol.read_data(sock=self.sock)
        decrypted_response = self.decrypt_message(encrypted_response)

        if code != ProtocolCodes.VERIFY_SIGN_UP_RESPONSE:
            print("TODO: We need to check why")
        return decrypted_response

    def resend_sign_up_code(self, email):
        message = ResendVerificationCodeRequest(email)
        self.client_server_protocol.send_data(sock=self.sock, code=ProtocolCodes.RESEND_VERIFICATION_CODE_REQUEST,
                                              message=message)
        code, message = self.client_server_protocol.read_data(sock=self.sock)
        if code != ProtocolCodes.RESEND_VERIFICATION_CODE_RESPONSE:
            print("TODO: We need to check why")
        return message

    def forgot_password(self, email):
        forgot_message = ForgotPasswordRequest(email=email)
        encrypted_message = self.wrap_with_encryption(forgot_message)

        self.client_server_protocol.send_data(sock=self.sock, code=ProtocolCodes.FORGOT_PASSWORD_REQUEST,
                                              message=encrypted_message)
        code, encrypted_response = self.client_server_protocol.read_data(sock=self.sock)
        decrypted_response = self.decrypt_message(encrypted_response)

        if code != ProtocolCodes.FORGOT_PASSWORD_RESPONSE:
            print("TODO: We need to check why")
        return decrypted_response

    def reset_password(self, email, password, reset_code):
        reset_message = ResetPasswordRequest(email=email, password=password, reset_code=reset_code)
        encrypted_message = self.wrap_with_encryption(reset_message)

        self.client_server_protocol.send_data(sock=self.sock, code=ProtocolCodes.RESET_PASSWORD_REQUEST,
                                              message=encrypted_message)
        code, encrypted_response = self.client_server_protocol.read_data(sock=self.sock)
        decrypted_response = self.decrypt_message(encrypted_response)

        if code != ProtocolCodes.RESET_PASSWORD_RESPONSE:
            print("TODO: We need to check why")
        return decrypted_response
