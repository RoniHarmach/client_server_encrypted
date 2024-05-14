from dataclasses import dataclass


@dataclass
class ForgotPasswordRequest:
    email: str

