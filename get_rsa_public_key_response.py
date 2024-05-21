from dataclasses import dataclass


@dataclass
class GetRsaPublicKeyResponse:
    rsa_public_key: bytes

