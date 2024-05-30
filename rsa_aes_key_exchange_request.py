from dataclasses import dataclass


@dataclass
class RsaAesKeyExchangeRequest:
    key: bytes