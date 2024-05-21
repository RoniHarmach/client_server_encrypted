from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from rsa import DecryptionError

from encryption_support_check_request import EncryptionSupportCheckRequest
from select_encryption_type_request import SelectEncryptionTypeRequest
from encrypted_aes_message import EncryptedAESMessage
from encryption import Encryption
from encryption_type import EncryptionType
from forgot_password_request import ForgotPasswordRequest
from login_request import LoginRequest
from protocol import Protocol
from protocol_codes import ProtocolCodes
from resend_verification_code_request import ResendVerificationCodeRequest
from reset_password_request import ResetPasswordRequest
from send_key_request import SendKeyRequest
from send_key_response import SendKeyResponse
from sign_up_request import SignUpRequest
from sign_up_verification_request import SignUpVerificationRequest


class UserLoginProtocol:
    client_server_protocol: Protocol = Protocol()
    sock =  None
    key = None
    encryption_type: EncryptionType = None
    is_secured_socket = False

    def __init__(self, sock):
        self.sock = sock

    def is_secure_socket(self):
        return self.is_secured_socket

    def open_secure_socket(self, encryption_type: str):
        if self.check_type(EncryptionType.RSA, encryption_type):
            return self.secure_with_rsa()
        elif self.check_type(EncryptionType.DIFFIE_HELLMAN, encryption_type):
            return self.secure_with_dfh()
        else:
            return False, f"Unsupported encryption type {encryption_type}"

    def check_type(self, encryption_type, value):
        try:
            enum_value = EncryptionType(value)
            return encryption_type == enum_value
        except ValueError:
            return False


    def generate_key(self):
        self.key = Encryption.generate_key()

    def select_encryption_type(self, encryption_type: EncryptionType):
        message = SelectEncryptionTypeRequest(encryption_type)
        self.client_server_protocol.send_data(sock=self.sock, code=ProtocolCodes.SELECT_ENCRYPTION_TYPE_REQUEST, message=message)

        code, message = self.client_server_protocol.read_data(self.sock)
        if code != ProtocolCodes.SELECT_ENCRYPTION_TYPE_RESPONSE:
            print("TODO: We need to check why")
        elif message.result:
            self.encryption_type = encryption_type
        return message

    def send_key_with_rsa(self, public_rsa_key, aes_key):
        try:
            encrypted_key = Encryption.encrypt_rsa_message(public_rsa_key, aes_key)
            message = SendKeyRequest(encrypted_key)
            self.client_server_protocol.send_data(sock=self.sock, code=ProtocolCodes.SEND_SHARED_KEY_REQUEST, message=message)
            code, message = self.client_server_protocol.read_data(self.sock)
            if code != ProtocolCodes.SEND_SHARED_KEY_RESPONSE:
                print("TODO: We need to check why")
            response = message
        except (ValueError, DecryptionError) as e:
            response = SendKeyResponse(result=False ,error=f"RSA exception: {e}")
        return response

    def encrypted_message(self, message):
        iv, encrypted_message = Encryption.aes_encrypt(self.key, message)
        return iv, encrypted_message

    def check_if_protocol_supported(self, encryption_type: EncryptionType):
        message = EncryptionSupportCheckRequest(encryption_type=encryption_type)
        self.client_server_protocol.send_data(sock=self.sock, code=ProtocolCodes.CHECK_ENCRYPTION_SUPPORT_REQUEST, message=message)
        code, response = self.client_server_protocol.read_data(sock=self.sock)
        if code != ProtocolCodes.CHECK_ENCRYPTION_SUPPORT_RESPONSE:
            print("TODO: We need to check why")
        return response.encryption_supported, response.error

    def get_server_public_rsa_key(self):
        self.client_server_protocol.send_data(sock=self.sock, code=ProtocolCodes.GET_RSA_PUBLIC_KEY_REQUEST, message=b'')
        code, response = self.client_server_protocol.read_data(sock=self.sock)
        if code != ProtocolCodes.GET_RSA_PUBLIC_KEY_RESPONSE:
            print("TODO: We need to check why")
        return response.rsa_public_key

    # 1. Check if server supports RSA
    # 2. Request from the server the public RSA key
    # 3. create AES key
    # 4. Encrypt AES key with the server public RSA key
    # 5. Send encrypted AES key to the server
    def secure_with_rsa(self):
        encryption_supported, error = self.check_if_protocol_supported(EncryptionType.RSA)
        if not encryption_supported:
            return False, error
        server_public_rsa_key = self.get_server_public_rsa_key()
        aes_key = Encryption.generate_key()
        response = self.send_key_with_rsa(server_public_rsa_key, aes_key)

        if response.result:
            self.key = aes_key
            self.is_secured_socket = True
        return response.result, response.error

    def secure_with_dfh(self):
        return False, "Not Implemented"

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
