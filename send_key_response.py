from dataclasses import dataclass
from typing import Optional


@dataclass
class SendKeyResponse:
    result: bool = False
    error: Optional[str] = None