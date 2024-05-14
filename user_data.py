from dataclasses import dataclass
from enum import Enum


class Status(Enum):
    WAITING_FOR_VERIFY = 1
    VERIFIED = 2


@dataclass
class UserData:
    email: str
    password: str
    status: Status

    def __json__(self):
        return {"email": self.email, "password": self.password, "status": self.status.name}

    @classmethod
    def from_json(cls, json):
        return cls(email=json["email"], password=json["password"], status=Status.__members__[json["status"]])



