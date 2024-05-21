from dataclasses import dataclass

from encryption_type import EncryptionType


@dataclass
class SelectEncryptionTypeRequest:
    result: bool
    error: str
