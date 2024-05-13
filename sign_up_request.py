from dataclasses import dataclass


@dataclass
class SignUpRequest:
    user: str
    email: str
    password: str

