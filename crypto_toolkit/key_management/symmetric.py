# coding: utf-8
# crypto_toolkit/key_management/symmetric.py

# Standard Library
import os
import json
from enum import Enum
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from collections import namedtuple
from typing import Optional, Union

# Third Party
import aiofiles
import aiofiles.os
from apscheduler.schedulers.asyncio import AsyncIOScheduler

# Utility
from crypto_toolkit.utils.kid import generate_kid


# ------------------------------------------------------------------------------

class LoadType(Enum):
    """
    최초 키 로드, 생성/업데이트 할 장소
    AWS KMS 같은 경우는 여기 추가 후 로직 구현
    """
    FILE = 'FILE'  # Required file_path argument when using


@dataclass
class FileLoadOptions:
    """LoadType.FILE 사용 시 필요한 옵션"""
    file_path: str


# ------------------------------------------------------------------------------


UsageMeta = namedtuple('UsageMeta', ['label', 'key_length_bytes'])


class UsageType(Enum):
    AES128 = UsageMeta('AES128', 16)           # 128 bits → 16 bytes
    AES256 = UsageMeta('AES256', 32)           # 256 bits → 32 bytes
    SHA256_HMAC = UsageMeta('SHA256_HMAC', 32) # 256 bits → 32 bytes
    SHA512_HMAC = UsageMeta('SHA512_HMAC', 64) # 512 bits → 64 bytes
    PASSWORD_PEPPER = UsageMeta('PASSWORD_PEPPER', 32) # 256 bits → 32 bytes


# ------------------------------------------------------------------------------


@dataclass
class SymmetricKey:
    """
    대칭 키를 저장하거나 불러올 때 사용하는 데이터 클래스
    """
    kid: str
    key: bytes
    usage_type: UsageType
    created_at: datetime
    expires_at: datetime
    algorithm: Optional[str] = None

    def __getitem__(self, key):
        return getattr(self, key)


def generate_symmetric_key(usage_type: UsageType, rotation_interval_days: int) -> SymmetricKey:
    """
    대칭 키 생성
    """
    key = os.urandom(usage_type.value.key_length_bytes)
    now = datetime.now(timezone.utc)
    kid = generate_kid(usage_type.value.label, now)
    
    # Set algorithm for HMAC keys
    algorithm = None
    if usage_type == UsageType.SHA256_HMAC:
        algorithm = 'sha256'
    elif usage_type == UsageType.SHA512_HMAC:
        algorithm = 'sha512'

    return SymmetricKey(
        kid=kid,
        key=key,
        usage_type=usage_type,
        created_at=now,
        expires_at=now + timedelta(days=rotation_interval_days),
        algorithm=algorithm
    )


async def load_symmetric_key(
    usage_type: UsageType,
    load_type: LoadType,
    rotation_interval_days: int,
    options: Optional[Union[FileLoadOptions]] = None,
) -> SymmetricKey:
    """
    대칭 키를 로드하는 함수
    """
    if not isinstance(load_type, LoadType):
        raise ValueError("load_type must be an instance of LoadType Enum")

    # 다른 로드 방식은, elif 문 추가로 구현하면 됨.
    if load_type == LoadType.FILE:
        if not isinstance(options, FileLoadOptions):
            raise TypeError("For FILE load_type, options must be a FileLoadOptions instance")

        # File Path 옵션 검증
        file_path = options.file_path
        if not file_path:
            raise ValueError("file_path is required when load_type is FILE")
        if not file_path.endswith('.json'):
            raise ValueError("file_path must point to a .json file")

        # 폴더 없으면 생성
        if not await aiofiles.os.path.exists(file_path):
            dir_path = os.path.dirname(file_path)
            if dir_path and not await aiofiles.os.path.exists(dir_path):
                await aiofiles.os.makedirs(dir_path)

            new_key = generate_symmetric_key(usage_type, rotation_interval_days)
            await save_symmetric_key(new_key, LoadType.FILE, options=options)
            return new_key

        # Json 형식으로 파일에서 SymmetricKey 객체 로드
        try:
            async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
                content = await f.read()
                key_data = json.loads(content)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON format in key file: {e}")
        except Exception as e:
            raise IOError(f"Failed to read key file: {e}")

        # 파일 존재하나 키 데이터 불일치
        required_fields = ['kid', 'key', 'usage_type', 'created_at', 'expires_at']
        if not all(field in key_data for field in required_fields):
            raise ValueError("Invalid key data in file")

        # datetime 로드 후 UTC 타임존 설정 (없으면 추가)
        created_at = datetime.fromisoformat(key_data['created_at'])
        expires_at = datetime.fromisoformat(key_data['expires_at'])
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        try:
            usage_type_enum = UsageType[key_data['usage_type']]
        except KeyError:
            raise ValueError(f"Unknown usage_type: {key_data['usage_type']}")

        return SymmetricKey(
            kid=key_data['kid'],
            key=bytes.fromhex(key_data['key']),
            usage_type=usage_type_enum,
            created_at=created_at,
            expires_at=expires_at
        )


async def save_symmetric_key(
    key: SymmetricKey,
    load_type: LoadType,
    options: Optional[Union[FileLoadOptions]] = None,
    ) -> None:
    """
    대칭 키 저장
    """
    if not isinstance(load_type, LoadType):
        raise ValueError("load_type must be an instance of LoadType Enum")

    if load_type == LoadType.FILE:
        if not isinstance(options, FileLoadOptions):
            raise TypeError("For FILE load_type, options must be a FileLoadOptions instance")

        # File Path 옵션 검증
        file_path = options.file_path
        if not file_path:
            raise ValueError("file_path is required when load_type is FILE")
        if not file_path.endswith('.json'):
            raise ValueError("file_path must point to a .json file")
        if not key:
            raise ValueError("key is required to save the symmetric key")

        key_data = {
            'kid': key.kid,
            'key': key.key.hex(),
            'usage_type': key.usage_type.name,
            'created_at': key.created_at.isoformat(),
            'expires_at': key.expires_at.isoformat()
        }

        async with aiofiles.open(file_path, 'w', encoding='utf-8') as f:
            await f.write(json.dumps(key_data, indent=2))


class SymmetricKeyRotator:
    """
    대칭 키 회전 클래스

    Lifespan에 추가하면 바로 사용 가능.

    예제:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        rotator = SymmetricKeyRotator(
            usage_type=UsageType.AES256,
            rotation_interval_days=30,
            load_type=LoadType.FILE,
            options=FileLoadOptions(file_path="./keys/aes_key.json")
        )
        await rotator.init()
        yield
        rotator.stop_scheduler()
    """
    def __init__(
        self,
        usage_type: UsageType,
        rotation_interval_days: int,
        load_type: LoadType,
        options: Optional[Union[FileLoadOptions]] = None
    ):
        # 무거운 작업은 init()으로 옵김: 생성자는 빠르게 반환
        self.scheduler = AsyncIOScheduler()
        self.usage_type = usage_type
        self.rotation_interval_days = rotation_interval_days
        self.load_type = load_type
        self.options = options
        self.current_key: SymmetricKey | None = None

        if self.load_type == LoadType.FILE:
            if not isinstance(self.options, FileLoadOptions):
                raise TypeError("For FILE load_type, options must be a FileLoadOptions instance")
            self.key_file = self.options.file_path
            if not self.key_file:
                raise ValueError("file_path is required when load_type is FILE")

    async def init(self) -> None:
        """
        비동기 초기화: 파일 I/O 같은 블로킹 작업 수행.
        lifespan에서 반드시 await rotator.init() 호출할 것.
        """
        self.current_key = await load_symmetric_key(
            self.usage_type,
            self.load_type,
            rotation_interval_days=self.rotation_interval_days,
            options=self.options
        )
        self._schedule_next_rotation()

    async def rotate_key(self) -> None:
        """키 회전 실행"""
        self.current_key = generate_symmetric_key(
            self.usage_type,
            self.rotation_interval_days
        )
        await save_symmetric_key(
            self.current_key,
            self.load_type,
            options=self.options
        )
        # 회전 후 다음 회전 예약
        self._schedule_next_rotation()

    def _schedule_next_rotation(self) -> None:
        """다음 키 회전 예약"""
        run_date = self.current_key.expires_at
        self.scheduler.add_job(
            self.rotate_key,
            "date",
            run_date=run_date
        )
        if not self.scheduler.running:
            self.scheduler.start()

    def stop_scheduler(self) -> None:
        """스케줄러 정지"""
        if hasattr(self, 'scheduler') and self.scheduler:
            self.scheduler.shutdown()
