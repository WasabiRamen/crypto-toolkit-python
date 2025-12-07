import hashlib
import hmac
from typing import Union
from dataclasses import dataclass

from crypto_toolkit.key_management.symmetric import SymmetricKey

"""
 Requires: key_management.symmetric.SymmetricKey
"""


@dataclass
class SHAHMACConfig:
    key: SymmetricKey


class SHAHMACHasher:
    def __init__(self, config: SHAHMACConfig, pepper: str | None = None):
        self.__algorithm = getattr(hashlib, config.key.algorithm)
        self.__key = config.key.key
        self.__PEPPER = pepper

    def __plain_with_pepper(self, plain: Union[str, bytes]) -> Union[str, bytes]:
        if self.__PEPPER:
            if isinstance(plain, str):
                return plain + self.__PEPPER
            elif isinstance(plain, bytes):
                return plain + self.__PEPPER.encode('utf-8')
        return plain

    def hash(self, plain: Union[str, bytes]) -> str:
        plain = self.__plain_with_pepper(plain)
        if isinstance(plain, str):
            plain = plain.encode('utf-8')
        hash_obj = hmac.new(self.__key, plain, self.__algorithm)
        return hash_obj.hexdigest()

    def verify(self, message: Union[str, bytes], expected_hmac: str) -> bool:
        calculated_hmac = self.hash(message)
        return hmac.compare_digest(calculated_hmac, expected_hmac)
