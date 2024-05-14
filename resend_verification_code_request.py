from dataclasses import dataclass


@dataclass
class ResendVerificationCodeRequest:
    user: str
