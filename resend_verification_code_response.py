from dataclasses import dataclass
from typing import Optional


@dataclass
class ResendVerificationCodeResponse:
    result: bool = False
    error: Optional[str] = None
