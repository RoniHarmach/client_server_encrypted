from dataclasses import dataclass


@dataclass
class EncryptedAESMessage:
    iv: any
    encrypted_message: any
