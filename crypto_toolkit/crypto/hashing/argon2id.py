
from dataclasses import dataclass
from enum import Enum

from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError, InvalidHash


@dataclass(frozen=True)
class Argon2idConfig:
    """
    Argon2id 해싱 구성.
    기본값은 Recommended 수준으로 설정됨.
    """
    time_cost: int = 3
    memory_cost: int = 65536  # KiB (64 MB)
    parallelism: int = 2
    hash_len: int = 32        # 해시 길이 (byte)
    salt_len: int = 16        # 솔트 길이 (byte)
    type: Type = Type.ID

class ARGON2_PROFILE(Enum):
    """
    Argon2id 해싱 프로파일 Enum

    커스텀 프로파일 사용 시에는 Argon2idConfig를 직접 생성하여 사용.
    """
    BASIC = Argon2idConfig(time_cost=2, memory_cost=32768, parallelism=1)
    RECOMMENDED = Argon2idConfig()  # 기본값 그대로
    STRONG = Argon2idConfig(time_cost=3, memory_cost=131072, parallelism=2)
    EXTREME = Argon2idConfig(time_cost=4, memory_cost=262144, parallelism=4)

class Argon2idHasher:
    def __init__(
        self,
        config: Argon2idConfig = ARGON2_PROFILE.RECOMMENDED,
        pepper: str | None = None
    ):
        config_value = config.value
        self.hasher = PasswordHasher(
            time_cost=config_value.time_cost,
            memory_cost=config_value.memory_cost,
            parallelism=config_value.parallelism,
            hash_len=config_value.hash_len,
            salt_len=config_value.salt_len,
            type=config_value.type,
        )
        self.__PEPPER = pepper

    def __plain_with_pepper(self, plain: str | None = None) -> str:
        """
        pepper가 설정된 경우, 평문에 pepper를 추가합니다.
        """
        if self.__PEPPER:
            return plain + self.__PEPPER
        return plain
    
    def password_hash(self, plain: str) -> str:
        """
            비밀번호 해싱
            Args:
                plain: 해싱할 비밀번호 문자열
            Returns:
                해싱된 비밀번호 문자열
        """
        if self.__PEPPER:
            plain = self.__plain_with_pepper(plain)

        return self.hasher.hash(plain)
    
    def password_verify(self, hash: str, plain: str) -> bool:
        """
            비밀번호 검증
            Args:
                hash: 해싱된 비밀번호 문자열
                plain: 검증할 비밀번호 문자열
            Returns:
                검증 결과 (True: 일치, False: 불일치)
        """
        if self.__PEPPER:
            plain = self.__plain_with_pepper(plain)
        try:
            self.hasher.verify(hash, plain)
            return True
        except (VerifyMismatchError, InvalidHash):
            return False
    
    def check_needs_rehash(self, hash: str) -> bool:
        """
            해시 재해싱 필요 여부 확인
            Args:
                hash: 해싱된 비밀번호 문자열
            Returns:
                재해싱 필요 여부 (True: 필요, False: 불필요)
        """
        return self.hasher.check_needs_rehash(hash)