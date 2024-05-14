from dataclasses import dataclass
from enum import Enum


class Status(Enum):
    WAITING_FOR_VERIFY = 1
    VERIFIED = 2


@dataclass
class UserData:
    password: str
    email: str
    status: Status

