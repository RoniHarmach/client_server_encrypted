from dataclasses import dataclass


@dataclass
class ResetPasswordRequest:
    email: str
    password: str
    reset_code: int

