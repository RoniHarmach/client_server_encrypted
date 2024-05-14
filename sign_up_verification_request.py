from dataclasses import dataclass


@dataclass
class SignUpVerificationRequest:
    email: str
    code: int

