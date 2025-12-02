# Standard Library
import string
import random
from enum import Enum
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import uuid4

# Third Party
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

class SymmetricKeyRotator:
    """대칭 키 회전 (AES, HMAC-SHA 등)"""

    @dataclass
    class SymmetricKey:
        kid: str
        key: bytes
        created_at: int
        expires_at: int

    class UsageType(Enum):
        AES = 'AES'
        HMAC = 'HMAC'

    def __init__(
        self, 
        usage: UsageType,
        rotation_interval_days: int = 30,
        key_length_bytes: int = 32  # 기본 256비트 키
        ):
        self.__rotation_interval_days = rotation_interval_days
        self.__key_length_bytes = key_length_bytes
        if not isinstance(usage, SymmetricKeyRotator.UsageType):
                    raise ValueError(f"usage must be a SymmetricKeyRotator.UsageType, got {usage}")
        self.__usage_type = usage.value


class RsaKeyRotator:
    """비대칭 키 회전 (RSA)"""

    @dataclass
    class RSAKeyPair:
        kid: str
        private_key: bytes
        public_key: bytes
        created_at: int
        expires_at: int

    def __init__(
        self, 
        rotation_interval_days: int = 90,
        key_size_bits: int = 2048
        ):
        pass

# def generate_kid(created_at: int) -> str:
#     """
#     RSA KEY ID 생성 유틸

#     키 형식 - yyyy-mm-dd_uuid4
#     """
#     created_date = datetime.fromtimestamp(created_at, timezone.utc).strftime("%Y-%m-%d")
#     kid = f"rsa-{created_date}-{str(uuid4())}"
#     return kid


# def generate_rsa_key_pair() -> RSAKeyPair:    
#     """
#     RSA 키 쌍 생성 유틸 함수
#     """
#     # 1. RSA 개인키 생성 (2048bit)
#     private_key = rsa.generate_private_key(
#         public_exponent=65537,
#         key_size=2048,
#         )

#     # 2. 개인키를 PEM 문자열로 내보내기
#     private_pem = private_key.private_bytes(
#         encoding=serialization.Encoding.PEM,
#         format=serialization.PrivateFormat.PKCS8,
#         encryption_algorithm=serialization.NoEncryption(),
#     ).decode("utf-8")

#     # 3. 공개키를 PEM 문자열로 내보내기
#     public_pem = private_key.public_key().public_bytes(
#         encoding=serialization.Encoding.PEM,
#         format=serialization.PublicFormat.SubjectPublicKeyInfo,
#     ).decode("utf-8")

#     created_at = int(datetime.now(timezone.utc).timestamp())
#     kid = generate_kid(created_at)

#     return RSAKeyPair(
#         kid=kid,
#         private_key=private_pem,
#         public_key=public_pem,
#         created_at=created_at
#     )


# async def key_save(file_path: str, key_string: str) -> None:
#     """
#     RSA 키(PK/공개키)를 PEM 파일로 저장하는 유틸 함수 (비동기)

#     Args:
#         file_path (str): PEM 파일 경로 (디렉터리가 없으면 생성)
#         key_string (str): 저장할 PEM 문자열
#     """
#     if not file_path.endswith(".pem"):
#         raise ValueError("file_path 확장자는 .pem 이어야 합니다.")

#     path = Path(file_path)
#     # 상위 디렉터리가 없을 경우 재귀적으로 생성
#     path.parent.mkdir(parents=True, exist_ok=True)
    
#     # 비동기 파일 쓰기
#     async with aiofiles.open(file_path, 'w') as f:
#         await f.write(key_string)


# # Standard Library
# import os
# from datetime import datetime, timezone
# from venv import create

# # Third Party
# from httpx import get
# from loguru import logger
# from pydantic import Field, BaseModel
# from apscheduler.schedulers.asyncio import AsyncIOScheduler
# from fastapi import FastAPI

# # SQLAlchemy
# from sqlalchemy.ext.asyncio import AsyncSession
# from sqlalchemy.future import select

# # APP Specific
# from app.shared.core.database import get_db
# from app.shared.core.settings import get_auth_settings
# from ...app.models import RSAKey

# from .generator import RSAKeyPair, generate_rsa_key_pair, key_save
# from .loader import load_private_key

# # 굳이 설정을 불러오기
# auth_settings = get_auth_settings()
# _key_rotation_days = auth_settings.SECRET_KEY_ROTATION_DAYS
# _access_token_expire_minutes = auth_settings.ACCESS_TOKEN_EXPIRE_MINUTES


# def time_now():
#     return datetime.now(timezone.utc)


# async def get_latest_key(db: AsyncSession):
#     """
#     만료가 되지 않은 키가 남아있다면 키를 Return 한다.
#     """
#     result = await db.execute(
#         select(RSAKey).order_by(RSAKey.created_at.desc()).limit(1)
#     )

#     last_key = result.scalars().first()

#     if last_key:
#         now = time_now()
#         if last_key.expires_at > now:
#             return last_key
    
#     return None


# async def create_key(
#         db: AsyncSession,
#         private_key_path: str,
#         public_key_path: str,
#         key_pair: RSAKeyPair,
#         expires_at: int,
#         verify_until: int,
#         ):
#     kid = key_pair.kid
#     created_at = key_pair.created_at
#     rsa_key = RSAKey(
#         kid=kid,
#         private_key_path=private_key_path,
#         public_key_path=public_key_path,
#         created_at=datetime.fromtimestamp(created_at, timezone.utc),
#         expires_at=datetime.fromtimestamp(expires_at, timezone.utc),
#         verify_until=datetime.fromtimestamp(verify_until, timezone.utc),
#     )
#     db.add(rsa_key)
#     await db.commit()
#     await db.refresh(rsa_key)
#     return rsa_key


# class RSAKeyRotation:
#     """
#     로컬 JWT 비밀 키 관리 유틸

#     차후 AWS로 관리하는 로직도 가져오겠음.

#     Lifespan에 추가하면 바로 사용 가능.
#     Auth 내에서만 사용 되어야함.

    

#     예제:
#     @asynccontextmanager
#     async def lifespan(app: FastAPI):
#         app.state.jwt_manager = RSAKeyRotation()
#     """
#     def __init__(
#             self, 
#             private_key_path: str = None,  # BasePath만 작성
#             public_key_path: str = None,   # BasePath만 작성
#             ):
#         # 무거운 작업은 init()으로 옮김: 생성자는 빠르게 반환
#         self.scheduler = AsyncIOScheduler()
#         self.current_key = None
#         self.current_kid = None
#         self.__PRIVATE_KEY_PATH = private_key_path
#         self.__PUBLIC_KEY_PATH = public_key_path

#         if not self.__PRIVATE_KEY_PATH.startswith('/'):
#             self.__PRIVATE_KEY_PATH = os.path.join(os.getcwd(), self.__PRIVATE_KEY_PATH)
#         if not self.__PUBLIC_KEY_PATH.startswith('/'):
#             self.__PUBLIC_KEY_PATH = os.path.join(os.getcwd(), self.__PUBLIC_KEY_PATH)

#     async def init(self, app: FastAPI) -> None:
#         """
#         비동기 초기화: 파일 I/O 같은 블로킹 작업은 스레드로 실행.
#         lifespan에서 반드시 await manager.init() 호출할 것.
#         """
#         # 스케줄 작업 및 DB 접근에 사용할 app 참조 저장
#         self._app = app
#         # Request 컨텍스트가 없는 환경이므로 app.state의 세션메이커를 사용
#         SessionLocal = getattr(app.state, "async_session_maker", None)
#         if SessionLocal is None:
#             raise RuntimeError("Async session maker is not initialized on app.state. Call init_db() first.")

#         async with SessionLocal() as db:
#             last_key_info = await get_latest_key(db)
#             if last_key_info:  # 서비스 내에는 개인키만 필요하므로, 개인키만 로드
#                 self.current_key = await load_private_key(last_key_info.private_key_path)
#                 self.current_kid = last_key_info.kid
#                 await self.create_schedule_next_rotation(int(last_key_info.expires_at.timestamp()))
#             else:
#                 await self.generate_and_store_new_key(app)
#                 # generate_and_store_new_key 내부에서 다음 회전 예약 수행

#         if not self.scheduler.running:
#             self.scheduler.start()

#     async def generate_and_store_new_key(self, app: FastAPI) -> None:
#         """
#         RSA 키 쌍 생성 및 저장 / 전역 변수 갱신
#         """
#         key_pair: RSAKeyPair = generate_rsa_key_pair()
#         private_key: str = key_pair.private_key
#         public_key: str = key_pair.public_key
#         created_at: int = key_pair.created_at
#         expired_at: int = created_at + (_key_rotation_days * 24 * 60 * 60)
#         verify_until: int = expired_at + (_access_token_expire_minutes * 60)

#         private_key_path = os.path.join(self.__PRIVATE_KEY_PATH, f"{key_pair.kid}.pem")
#         public_key_path = os.path.join(self.__PUBLIC_KEY_PATH, f"{key_pair.kid}.pem")

#         # 실제 파일 경로로 저장
#         await key_save(private_key_path, private_key)
#         await key_save(public_key_path, public_key)
#         # DB 저장 (Request 없이 app.state의 세션메이커 사용)
#         SessionLocal = getattr(app.state, "async_session_maker", None)
#         if SessionLocal is None:
#             raise RuntimeError("Async session maker is not initialized on app.state. Call init_db() first.")
#         async with SessionLocal() as db:
#             await create_key(
#                 db,
#                 private_key_path=private_key_path,
#                 public_key_path=public_key_path,
#                 key_pair=key_pair,
#                 expires_at=expired_at,
#                 verify_until=verify_until,
#             )

#         self.current_key = await load_private_key(private_key_path)
#         self.current_kid = key_pair.kid

#         logger.info(f"New RSA Key Generated and Stored. KID: {key_pair.kid}")

#         await self.create_schedule_next_rotation(expired_at)

#     async def create_schedule_next_rotation(self, timestamp: int):
#         run_dt = datetime.fromtimestamp(timestamp, timezone.utc)
#         logger.info(f"Scheduling next RSA key rotation at {run_dt}")
#         # 단발성 예약(다음 실행 시 다시 예약하므로 반복 트리거 불필요)
#         self.scheduler.add_job(
#             self.generate_and_store_new_key,
#             "date",
#             run_date=run_dt,
#             args=[getattr(self, "_app", None)],
#             id="rsa_key_rotate",
#             replace_existing=True
#         )

