from dataclasses import dataclass


@dataclass
class ForgotPasswordRequest:
    user: str

