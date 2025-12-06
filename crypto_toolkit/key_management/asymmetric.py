# coding: utf-8
# crypto_toolkit/key_management/asymmetric.py

# Standard Library
import os
import json
from enum import Enum
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional, Union

# Third Party
import aiofiles
import aiofiles.os
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

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
    private_key_path: str
    public_key_path: str


# ------------------------------------------------------------------------------


class RSAKeySize(Enum):
    """
    RSA 키 크기 옵션
    """
    RSA2048 = 2048
    RSA4096 = 4096


# ------------------------------------------------------------------------------


@dataclass
class AsymmetricKeyPair:
    """
    비대칭 키 쌍을 저장하거나 불러올 때 사용하는 데이터 클래스
    """
    kid: str
    private_key: bytes
    public_key: bytes
    key_size: RSAKeySize
    created_at: datetime
    expires_at: datetime

    def __getitem__(self, key):
        return getattr(self, key)


def generate_asymmetric_key(key_size: RSAKeySize, rotation_interval_days: int) -> AsymmetricKeyPair:
    """
    비대칭 키 쌍 생성 (RSA)
    """
    # RSA 키 쌍 생성
    private_key_obj = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size.value,
        backend=default_backend()
    )
    public_key_obj = private_key_obj.public_key()

    # PEM 형식으로 직렬화
    private_pem = private_key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key_obj.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    now = datetime.now(timezone.utc)
    kid = generate_kid(f'RSA{key_size.value}', now)

    return AsymmetricKeyPair(
        kid=kid,
        private_key=private_pem,
        public_key=public_pem,
        key_size=key_size,
        created_at=now,
        expires_at=now + timedelta(days=rotation_interval_days)
    )


async def load_asymmetric_key(
    key_size: RSAKeySize,
    load_type: LoadType,
    rotation_interval_days: int,
    options: Optional[Union[FileLoadOptions]] = None,
) -> AsymmetricKeyPair:
    """
    비대칭 키 쌍을 로드하는 함수
    """
    if not isinstance(load_type, LoadType):
        raise ValueError("load_type must be an instance of LoadType Enum")

    # 다른 로드 방식은, elif 문 추가로 구현하면 됨.
    if load_type == LoadType.FILE:
        if not isinstance(options, FileLoadOptions):
            raise TypeError("For FILE load_type, options must be a FileLoadOptions instance")

        # File Path 옵션 검증
        private_key_path = options.private_key_path
        public_key_path = options.public_key_path
        
        if not private_key_path or not public_key_path:
            raise ValueError("private_key_path and public_key_path are required when load_type is FILE")
        if not private_key_path.endswith('.json') or not public_key_path.endswith('.json'):
            raise ValueError("private_key_path and public_key_path must point to .json files")

        # 폴더 없으면 생성 및 새 키 생성
        if not await aiofiles.os.path.exists(private_key_path) or not await aiofiles.os.path.exists(public_key_path):
            # 디렉토리 생성
            for path in [private_key_path, public_key_path]:
                dir_path = os.path.dirname(path)
                if dir_path and not await aiofiles.os.path.exists(dir_path):
                    await aiofiles.os.makedirs(dir_path)

            new_key_pair = generate_asymmetric_key(key_size, rotation_interval_days)
            await save_asymmetric_key(new_key_pair, LoadType.FILE, options=options)
            return new_key_pair

        # Private Key 로드
        try:
            async with aiofiles.open(private_key_path, 'r', encoding='utf-8') as f:
                content = await f.read()
                private_data = json.loads(content)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON format in private key file: {e}")
        except Exception as e:
            raise IOError(f"Failed to read private key file: {e}")

        # Public Key 로드
        try:
            async with aiofiles.open(public_key_path, 'r', encoding='utf-8') as f:
                content = await f.read()
                public_data = json.loads(content)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON format in public key file: {e}")
        except Exception as e:
            raise IOError(f"Failed to read public key file: {e}")

        # 데이터 검증
        required_private_fields = ['kid', 'private_key', 'key_size', 'created_at', 'expires_at']
        required_public_fields = ['kid', 'public_key']
        
        if not all(field in private_data for field in required_private_fields):
            raise ValueError("Invalid private key data in file")
        if not all(field in public_data for field in required_public_fields):
            raise ValueError("Invalid public key data in file")
        if private_data['kid'] != public_data['kid']:
            raise ValueError("Private and public key kid mismatch")

        # datetime 로드 후 UTC 타임존 설정 (없으면 추가)
        created_at = datetime.fromisoformat(private_data['created_at'])
        expires_at = datetime.fromisoformat(private_data['expires_at'])
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        try:
            key_size_enum = RSAKeySize[private_data['key_size']]
        except KeyError:
            raise ValueError(f"Unknown key_size: {private_data['key_size']}")

        return AsymmetricKeyPair(
            kid=private_data['kid'],
            private_key=private_data['private_key'].encode('utf-8'),
            public_key=public_data['public_key'].encode('utf-8'),
            key_size=key_size_enum,
            created_at=created_at,
            expires_at=expires_at
        )


async def save_asymmetric_key(
    key_pair: AsymmetricKeyPair,
    load_type: LoadType,
    options: Optional[Union[FileLoadOptions]] = None,
) -> None:
    """
    비대칭 키 쌍 저장
    """
    if not isinstance(load_type, LoadType):
        raise ValueError("load_type must be an instance of LoadType Enum")

    if load_type == LoadType.FILE:
        if not isinstance(options, FileLoadOptions):
            raise TypeError("For FILE load_type, options must be a FileLoadOptions instance")

        # File Path 옵션 검증
        private_key_path = options.private_key_path
        public_key_path = options.public_key_path
        
        if not private_key_path or not public_key_path:
            raise ValueError("private_key_path and public_key_path are required when load_type is FILE")
        if not private_key_path.endswith('.json') or not public_key_path.endswith('.json'):
            raise ValueError("private_key_path and public_key_path must point to .json files")
        if not key_pair:
            raise ValueError("key_pair is required to save the asymmetric key")

        # Private Key 데이터
        private_data = {
            'kid': key_pair.kid,
            'private_key': key_pair.private_key.decode('utf-8'),
            'key_size': key_pair.key_size.name,
            'created_at': key_pair.created_at.isoformat(),
            'expires_at': key_pair.expires_at.isoformat()
        }

        # Public Key 데이터
        public_data = {
            'kid': key_pair.kid,
            'public_key': key_pair.public_key.decode('utf-8'),
            'key_size': key_pair.key_size.name,
            'created_at': key_pair.created_at.isoformat(),
            'expires_at': key_pair.expires_at.isoformat()
        }

        # Private Key 저장
        async with aiofiles.open(private_key_path, 'w') as f:
            await f.write(json.dumps(private_data, indent=2))

        # Public Key 저장
        async with aiofiles.open(public_key_path, 'w') as f:
            await f.write(json.dumps(public_data, indent=2))


class AsymmetricKeyRotator:
    """
    비대칭 키 회전 클래스

    Lifespan에 추가하면 바로 사용 가능.

    예제:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        rotator = AsymmetricKeyRotator(
            key_size=RSAKeySize.RSA2048,
            rotation_interval_days=90,
            load_type=LoadType.FILE,
            options=FileLoadOptions(
                private_key_path="./keys/private_key.json",
                public_key_path="./keys/public_key.json"
            )
        )
        await rotator.init()
        yield
        rotator.stop_scheduler()
    """
    def __init__(
        self,
        key_size: RSAKeySize,
        rotation_interval_days: int,
        load_type: LoadType,
        options: Optional[Union[FileLoadOptions]] = None
    ):
        # 무거운 작업은 init()으로 옮김: 생성자는 빠르게 반환
        self.scheduler = AsyncIOScheduler()
        self.key_size = key_size
        self.rotation_interval_days = rotation_interval_days
        self.load_type = load_type
        self.options = options
        self.current_key_pair: AsymmetricKeyPair | None = None

        if self.load_type == LoadType.FILE:
            if not isinstance(self.options, FileLoadOptions):
                raise TypeError("For FILE load_type, options must be a FileLoadOptions instance")
            if not self.options.private_key_path or not self.options.public_key_path:
                raise ValueError("private_key_path and public_key_path are required when load_type is FILE")

    async def init(self) -> None:
        """
        비동기 초기화: 파일 I/O 같은 블로킹 작업 수행.
        lifespan에서 반드시 await rotator.init() 호출할 것.
        """
        self.current_key_pair = await load_asymmetric_key(
            self.key_size,
            self.load_type,
            rotation_interval_days=self.rotation_interval_days,
            options=self.options
        )
        self._schedule_next_rotation()

    async def rotate_key(self) -> None:
        """키 회전 실행"""
        self.current_key_pair = generate_asymmetric_key(
            self.key_size,
            self.rotation_interval_days
        )
        await save_asymmetric_key(
            self.current_key_pair,
            self.load_type,
            options=self.options
        )
        # 회전 후 다음 회전 예약
        self._schedule_next_rotation()

    def _schedule_next_rotation(self) -> None:
        """다음 키 회전 예약"""
        run_date = self.current_key_pair.expires_at
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