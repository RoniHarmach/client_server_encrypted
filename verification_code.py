from dataclasses import dataclass
from datetime import datetime


@dataclass
class VerificationCode:
    code: str
    expiration_time: datetime

    def __json__(self):
        return {"code": self.code, "expiration_time": self.expiration_time.timestamp()}

    @classmethod
    def from_json(cls, json):
        return cls(code=json["code"], expiration_time=datetime.fromtimestamp(json["expiration_time"]))


