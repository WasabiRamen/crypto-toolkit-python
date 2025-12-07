# crypto_toolkit/crypto/hashing/bcrypt.py
# bcrypt 해싱 유틸리티
from typing import Optional
from enum import Enum

import bcrypt


class BcryptRounds(Enum):
    """bcrypt 해싱 라운드 수 (Cost) / 추천 값"""
    LITE = 10
    RECOMMENDED = 12
    STRONG = 14

class BcryptVerificationError(Exception):
    """해싱 검증 실패 예외"""
    pass


class BcryptHasher:
    """
    bcrypt Utility

    Requires Key: None
    Max Input Length: 72 bytes (bcrypt 제한) / 주의 요망 / 

    제한되는 글자수: 
        한국어 기준 약 24자
        특수기호 + 영어 + 숫자 기준 약 72자

    사용시 asyncio.to_thread 권장

    Hash -> DB 바로 저장 가능
    """
    def __init__(self, bcrypt_rounds: BcryptRounds = BcryptRounds.RECOMMENDED, pepper: str | None = None):
        """
        bcrypt_rounds: bcrypt 해싱 라운드 수 (Cost)

        높으면 보안성 강화, 속도 저하
        cost를 1씩 올릴 때마다, 해싱 속도는 약 2배 느려집니다.

        Code Space 기준 대략
            10 라운드: 20ms
            12 라운드: 80ms
            14 라운드: 300ms

        API 서버: 12 > 권장
        민감 데이터: 14 > 권장

        pepper만 제시 가능함. 버전관리는 별도 서버로직에 포함시켜야함. (key_management/pepper.py)

        Args:
            bcrypt_rounds: bcrypt 해싱 라운드 수 (default: 12, 최초에만 설정 가능함, 이후 변경 불가)
            pepper: (선택사항) plain + pepper 방식으로 보안 강화
        """

        self.__BCRYPT_ROUNDS: int = bcrypt_rounds.value
        self.__PEPPER: str | None = pepper

    def __plain_with_pepper(self, plain: str | None = None) -> str:
        """
        pepper가 설정된 경우, 평문에 pepper를 추가합니다.
        """
        if self.__PEPPER:
            return plain + self.__PEPPER
        return plain
    
    def password_hash(self, plain: str) -> str:
        """
        bcrypt로 해싱하여 utf-8 문자열로 반환합니다.
        """
        if self.__PEPPER:
            plain = self.__plain_with_pepper(plain)
        salt = bcrypt.gensalt(rounds=self.__BCRYPT_ROUNDS)
        hashed = bcrypt.hashpw(plain.encode('utf-8'), salt)
        encode_hashed = hashed.decode('utf-8')
        return encode_hashed
    
    def password_verify(self, hashed: str, plain: str) -> None:
        """평문 비밀번호와 해시를 비교합니다. bcrypt.checkpw는 안전한 비교를 수행합니다."""
        if self.__PEPPER:
            plain = self.__plain_with_pepper(plain)
        if not bcrypt.checkpw(plain.encode('utf-8'), hashed.encode('utf-8')):
            raise BcryptVerificationError("비밀번호가 일치하지 않습니다.")
        

    def check_needs_rehash(self, stored_hash: bytes) -> bool:
        """
        bcrypt 해시 재해싱 필요 여부 확인

        Args:
            stored_hash: 기존 해시 (bytes)
            current_rounds: 현재 설정된 bcrypt rounds (예: 12)

        Returns:
            bool: 재해싱 필요 여부
        """
        parts = stored_hash.decode('utf-8').split('$')
        if len(parts) < 3:
            raise ValueError("잘못된 bcrypt 해시 형식")
        
        stored_rounds = int(parts[2])
        
        return stored_rounds < self.__BCRYPT_ROUNDS

