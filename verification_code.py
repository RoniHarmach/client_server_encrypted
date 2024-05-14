from dataclasses import dataclass
from datetime import datetime


@dataclass
class VerificationCode:
    code: str
    expiration_time: datetime
