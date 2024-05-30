from dataclasses import dataclass


@dataclass
class RsaPublicKeyResponse:
    rsa_public_key: bytes

