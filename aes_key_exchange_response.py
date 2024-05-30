from dataclasses import dataclass
from typing import Optional


@dataclass
class AesKeyExchangeResponse:
    result: bool = False
    error: Optional[str] = None