from dataclasses import dataclass
from typing import Optional

from encryption_type import EncryptionType


@dataclass
class EncryptionSupportCheckResponse:
    encryption_supported: bool
    error: Optional[str] = None
