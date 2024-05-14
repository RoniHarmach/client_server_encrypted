from dataclasses import dataclass


@dataclass
class SignUpVerificationRequest:
    user: str
    code: str

