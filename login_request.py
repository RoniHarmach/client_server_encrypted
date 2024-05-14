from dataclasses import dataclass


@dataclass
class LoginRequest:
    email: str
    password: str

