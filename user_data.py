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
    salt: str

    def __json__(self):
        return {"email": self.email, "password": self.password, "salt": self.salt,  "status": self.status.name}

    def __hash__(self):
        # Hash based on the email and password attributes
        return hash(self.email)

    @classmethod
    def from_json(cls, json):
        salt = json.get("salt", "")  # Get salt from JSON data, default to empty string if missing
        return cls(email=json["email"], password=json["password"], salt=salt, status=Status.__members__[json["status"]])



