from dataclasses import dataclass
from typing import Optional


@dataclass
class SignUpVerificationResponse:
    result: bool = False
    error: Optional[str] = None

