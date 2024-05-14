from dataclasses import dataclass
from typing import Optional


@dataclass
class ForgotPasswordResponse:
    result: bool = False
    error: Optional[str] = None
