# Standard Library
import os
from enum import Enum
from datetime import datetime
from dataclasses import dataclass

# Third Party
from apscheduler.schedulers.asyncio import AsyncIOScheduler

# Utility
from hashing.key_rotator.util import generate_kid


class UsageType(Enum):
    AES128 = 'AES128'
    AES256 = 'AES256'
    SHA256_HMAC = 'SHA256_HMAC'
    SHA512_HMAC = 'SHA512_HMAC'


class LoadType(Enum):
    """
    최초 키 로드 / 생성할 장소

    AWS KMS 같은거는 여기다가 타입 추가해두고 로직 구현 하면 됨
    """
    FILE = 'FILE'


class SymmetricKeyRotator:
    """대칭 키 회전 (AES, HMAC-SHA 등)"""

    @dataclass
    class SymmetricKey:
        """
        대칭 키를 저장하거나 불러올 때, 사용하는 데이터 클래스
        """
        kid: str
        key: bytes
        created_at: datetime
        expires_at: datetime

    def __get_byte_length(self) -> int:
        """
        키 길이 바이트 단위 반환
        
        필요시 Return 값 수정하고 사용
        """
        if self.__usage_type == UsageType.AES128.value:
            return 16  # 128비트
        elif self.__usage_type == UsageType.AES256.value:
            return 32  # 256비트
        elif self.__usage_type == UsageType.SHA256_HMAC.value:
            return 32
        elif self.__usage_type == UsageType.SHA512_HMAC.value:
            return 64
        else:
            raise ValueError(f"Unsupported usage type: {self.__usage_type}")

    def __generate_key(self) -> SymmetricKey:
        """
        키 생성 로직
        """
        key = os.urandom(self.__key_length_bytes)
        now = datetime.now(datetime.timezone.utc)
        kid = generate_kid(self.__usage_type, now)
        result = self.SymmetricKey(
            kid=kid,
            key=key,
            created_at=now,
            expires_at=now + datetime.timedelta(days=self.__rotation_interval_days)
        )
        return result
        
    def __load_key_or_generate(self, load_type: LoadType, **kwargs) -> SymmetricKey:
        """
        키 로드 (최초 1회만 호출)
        
        Args:
            load_type: 로드 타입
            **kwargs: load_type에 따른 추가 매개변수
                - FILE: path (str) - 파일 경로
                - 추가 타입은 여기에 문서화
        """
        if load_type == LoadType.FILE:
            # 파일 경로 필요
            path = kwargs.get('path')
            if not path:
                raise ValueError("Required parameter 'path' for FILE load_type")
            
            # 파일이 없다면
            if not os.path.exists(path):
                key = self.__generate_key()
                # 파일로 저장
                with open(path, 'wb') as f:
                    f.write(key.key)
                return key

            return key
        
        # 추가 LoadType은 여기에 elif로 구현
        else:
            raise ValueError(f"Not supported load_type: {load_type}")

    def __init__(
        self, 
        usage: UsageType,
        load_type: LoadType,
        rotation_interval_days: int = 30,
        key_path: str | None = None  # load_type이 FILE일 때만 사용
        ):
        if not isinstance(usage, UsageType):
            raise ValueError(f"usage must be a UsageType, got {usage}")
        
        self.__usage_type = usage.value
        self.__key_length_bytes = self.__get_byte_length()
        self.__rotation_interval_days = rotation_interval_days
        self.__load_type = load_type
        
        if self.__load_type == LoadType.FILE and not key_path:
            raise ValueError("path parameter is required when load_type is FILE")
        
        self.__key_path = key_path
        
        self.current_key = self.__load_key_or_generate(
            self.__load_type,
            path=self.__key_path
        )
    
    async def next_rotation_scheduler(self):
        """
        다음 키 회전 스케줄러 설정
        """
        scheduler = AsyncIOScheduler()
        scheduler.add_job(
            self.rotate_key,
            'interval',
            days=self.__rotation_interval_days,
            next_run_time=datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=5)  # 테스트용 즉시 실행
        )
        scheduler.start()

    