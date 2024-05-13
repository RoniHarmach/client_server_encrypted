from dataclasses import dataclass


@dataclass
class LoginRequest:
    user: str
    password: str

