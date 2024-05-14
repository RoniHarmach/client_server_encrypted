from dataclasses import dataclass


@dataclass
class SignUpRequest:
    email: str
    password: str

