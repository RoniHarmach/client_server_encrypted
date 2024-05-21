from dataclasses import dataclass

from encryption_type import EncryptionType


@dataclass
class SelectEncryptionTypeRequest:
    encryption_type: EncryptionType
