from dataclasses import dataclass
from enum import Enum

from encryption import Encryption, EncryptionData


class Status(Enum):
    WAITING_FOR_VERIFY = 1
    VERIFIED = 2


@dataclass
class UserData:
    email: str
    password: str
    status: Status
    salt: EncryptionData.salt

    def __json__(self):
        return {"email": self.email, "password": self.password, "salt": self.salt,  "status": self.status.name}

    @classmethod
    def from_json(cls, json):
        salt = json.get("salt", "")  # Get salt from JSON data, default to empty string if missing
        return cls(email=json["email"], password=json["password"], salt=salt, status=Status.__members__[json["status"]])



