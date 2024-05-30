from dataclasses import dataclass
from typing import Optional


@dataclass
class DhPubKeyResponse:
    server_public_key: int
    result: bool
    error: Optional[str] = None
