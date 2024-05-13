from dataclasses import dataclass
from typing import Optional


@dataclass
class LoginResponse:
    result: bool = False
    error: Optional[str] = None
