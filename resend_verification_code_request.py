from dataclasses import dataclass


@dataclass
class ResendVerificationCodeRequest:
    email: str
