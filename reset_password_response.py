from dataclasses import dataclass
from typing import Optional


@dataclass
class ResetPasswordResponse:
    result: bool = False
    error: Optional[str] = None
