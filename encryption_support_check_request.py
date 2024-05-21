from dataclasses import dataclass

from encryption_type import EncryptionType


@dataclass
class EncryptionSupportCheckRequest:
    encryption_type: EncryptionType
