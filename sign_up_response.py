from dataclasses import dataclass
from typing import Optional


@dataclass
class SignUpResponse:
    result: bool = False
    error: Optional[str] = None

