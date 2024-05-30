from dataclasses import dataclass


@dataclass
class DhAesKeyExchangeRequest:
    key: bytes
    iv: any
