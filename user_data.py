from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional


class Status(Enum):
    WAITING_FOR_VERIFY = 1
    VERIFIED = 2


@dataclass
class UserData:
    user: str
    password: str
    email: str
    status: Status

