from dataclasses import dataclass


@dataclass
class SendKeyRequest:
    key: bytes