from dataclasses import dataclass


@dataclass
class DhPubKeyRequest:
    client_public_key: int
