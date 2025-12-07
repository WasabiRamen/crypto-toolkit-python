# Crypto Toolkit

Python 암호화 라이브러리

## 설치

```bash
pip install crypto-toolkit
```

## 사용법

### 1. 일반 사용

#### 1.1 비밀번호 해싱 - Bcrypt

```python
from crypto_toolkit.crypto.hashing.bcrypt import BcryptHasher, BcryptRounds

# Hasher 초기화
hasher = BcryptHasher(bcrypt_rounds=BcryptRounds.RECOMMENDED)

# 비밀번호 해싱
hashed = hasher.password_hash("my_password")

# 비밀번호 검증
try:
    hasher.password_verify(hashed, "my_password")
    print("비밀번호 일치")
except BcryptVerificationError:
    print("비밀번호 불일치")
```

#### 1.2 비밀번호 해싱 - Argon2id

```python
from crypto_toolkit.crypto.hashing.argon2id import Argon2idHasher, ARGON2_PROFILE

# Hasher 초기화
hasher = Argon2idHasher(config=ARGON2_PROFILE.RECOMMENDED)

# 비밀번호 해싱
hashed = hasher.password_hash("my_password")

# 비밀번호 검증
if hasher.password_verify(hashed, "my_password"):
    print("비밀번호 일치")
else:
    print("비밀번호 불일치")
```

#### 1.3 대칭키 암호화 - AES

```python
from crypto_toolkit.crypto.symmetric.aes import AESCryptor
from crypto_toolkit.key_management.symmetric import generate_symmetric_key, UsageType

# 키 생성
key_data = generate_symmetric_key(UsageType.AES256, rotation_interval_days=30)
cryptor = AESCryptor(key_data.key)

# 암호화
plaintext = b"sensitive data"
iv, ciphertext = cryptor.encrypt(plaintext)

# 복호화
decrypted = cryptor.decrypt(iv, ciphertext)
print(decrypted)  # b"sensitive data"
```

#### 1.4 메시지 서명 - HMAC

```python
from crypto_toolkit.crypto.hashing.sha_hmac import SHAHMACHasher, SHAHMACConfig
from crypto_toolkit.key_management.symmetric import generate_symmetric_key, UsageType

# 키 생성 및 설정
hmac_key = generate_symmetric_key(UsageType.SHA256_HMAC, rotation_interval_days=30)
config = SHAHMACConfig(key=hmac_key)
hasher = SHAHMACHasher(config=config)

# 서명 생성
message = "important message"
signature = hasher.hash(message)

# 서명 검증
is_valid = hasher.verify(message, signature)
print(f"서명 유효: {is_valid}")
```

---

### 2. FastAPI 사용 (lifespan + state)

#### 2.1 비밀번호 인증 - Bcrypt

```python
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from crypto_toolkit.crypto.hashing.bcrypt import BcryptHasher, BcryptRounds, BcryptVerificationError

class UserRegister(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

@asynccontextmanager
async def lifespan(app: FastAPI):
    # 시작: Hasher 및 DB 초기화
    app.state.hasher = BcryptHasher(bcrypt_rounds=BcryptRounds.RECOMMENDED)
    app.state.users_db = {}
    yield
    # 종료: 필요시 정리 작업

app = FastAPI(lifespan=lifespan)

@app.post("/register")
async def register(user: UserRegister, request: Request):
    hasher = request.app.state.hasher
    users_db = request.app.state.users_db
    
    if user.username in users_db:
        raise HTTPException(status_code=400, detail="User already exists")
    
    hashed_password = hasher.password_hash(user.password)
    users_db[user.username] = hashed_password
    return {"message": "User registered"}

@app.post("/login")
async def login(user: UserLogin, request: Request):
    hasher = request.app.state.hasher
    users_db = request.app.state.users_db
    
    if user.username not in users_db:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    try:
        hasher.password_verify(users_db[user.username], user.password)
        return {"message": "Login successful"}
    except BcryptVerificationError:
        raise HTTPException(status_code=401, detail="Invalid credentials")
```

#### 2.2 메시지 서명/검증 - HMAC (키 자동 로테이션)

```python
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from crypto_toolkit.crypto.hashing.sha_hmac import SHAHMACHasher, SHAHMACConfig
from crypto_toolkit.key_management.symmetric import (
    SymmetricKeyRotator,
    UsageType,
    LoadType,
    FileLoadOptions
)

class MessageSign(BaseModel):
    message: str

class MessageVerify(BaseModel):
    message: str
    signature: str

@asynccontextmanager
async def lifespan(app: FastAPI):
    # 시작: 키 로테이터 초기화
    rotator = SymmetricKeyRotator(
        usage_type=UsageType.SHA256_HMAC,
        rotation_interval_days=30,
        load_type=LoadType.FILE,
        options=FileLoadOptions(file_path="./keys/hmac_key.json")
    )
    await rotator.init()
    
    # state에 저장
    app.state.hmac_rotator = rotator
    app.state.hmac_hasher = SHAHMACHasher(
        config=SHAHMACConfig(key=rotator.current_key)
    )
    
    yield
    
    # 종료: 로테이터 중지
    rotator.stop_scheduler()

app = FastAPI(lifespan=lifespan)

@app.post("/sign")
async def sign_message(data: MessageSign, request: Request):
    hasher = request.app.state.hmac_hasher
    signature = hasher.hash(data.message)
    return {"message": data.message, "signature": signature}

@app.post("/verify")
async def verify_message(data: MessageVerify, request: Request):
    hasher = request.app.state.hmac_hasher
    is_valid = hasher.verify(data.message, data.signature)
    
    if not is_valid:
        raise HTTPException(status_code=400, detail="Invalid signature")
    
    return {"valid": True}

@app.get("/current-key")
async def get_current_key(request: Request):
    rotator = request.app.state.hmac_rotator
    key = rotator.current_key
    return {"kid": key.kid, "expires_at": key.expires_at.isoformat()}
```

#### 2.3 AES 암호화/복호화 (키 자동 로테이션)

```python
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from pydantic import BaseModel
from crypto_toolkit.crypto.symmetric.aes import AESCryptor
from crypto_toolkit.key_management.symmetric import (
    SymmetricKeyRotator,
    UsageType,
    LoadType,
    FileLoadOptions
)

class EncryptRequest(BaseModel):
    plaintext: str

class DecryptRequest(BaseModel):
    iv: str  # hex string
    ciphertext: str  # hex string

@asynccontextmanager
async def lifespan(app: FastAPI):
    # 시작: AES 키 로테이터 초기화
    rotator = SymmetricKeyRotator(
        usage_type=UsageType.AES256,
        rotation_interval_days=30,
        load_type=LoadType.FILE,
        options=FileLoadOptions(file_path="./keys/aes_key.json")
    )
    await rotator.init()
    
    # state에 저장
    app.state.aes_rotator = rotator
    app.state.aes_cryptor = AESCryptor(rotator.current_key.key)
    
    yield
    
    # 종료: 로테이터 중지
    rotator.stop_scheduler()

app = FastAPI(lifespan=lifespan)

@app.post("/encrypt")
async def encrypt(data: EncryptRequest, request: Request):
    cryptor = request.app.state.aes_cryptor
    plaintext_bytes = data.plaintext.encode('utf-8')
    
    iv, ciphertext = cryptor.encrypt(plaintext_bytes)
    
    return {
        "iv": iv.hex(),
        "ciphertext": ciphertext.hex()
    }

@app.post("/decrypt")
async def decrypt(data: DecryptRequest, request: Request):
    cryptor = request.app.state.aes_cryptor
    
    iv = bytes.fromhex(data.iv)
    ciphertext = bytes.fromhex(data.ciphertext)
    
    plaintext_bytes = cryptor.decrypt(iv, ciphertext)
    
    return {
        "plaintext": plaintext_bytes.decode('utf-8')
    }
```

## 주요 기능

- **비밀번호 해싱**: Bcrypt, Argon2id
- **대칭키 암호화**: AES-128/256
- **메시지 인증**: HMAC (SHA-256/512)
- **키 관리**: 자동 키 로테이션 지원
- **FastAPI 통합**: lifespan 및 state 기반 설정

## License

MIT
