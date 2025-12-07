# coding: utf-8
# tests/test_fastapi_integration.py

import pytest
import tempfile
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Depends
from fastapi.testclient import TestClient
from pydantic import BaseModel

from crypto_toolkit.crypto.hashing.argon2id import Argon2idHasher, ARGON2_PROFILE
from crypto_toolkit.crypto.hashing.bcrypt import BcryptHasher, BcryptRounds, BcryptVerificationError
from crypto_toolkit.crypto.hashing.sha_hmac import SHAHMACHasher, SHAHMACConfig
from crypto_toolkit.key_management.symmetric import (
    generate_symmetric_key,
    UsageType,
    SymmetricKeyRotator,
    LoadType,
    FileLoadOptions
)


# ==================== Pydantic Models ====================

class UserRegister(BaseModel):
    username: str
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class MessageSign(BaseModel):
    message: str


class MessageVerify(BaseModel):
    message: str
    signature: str


# ==================== FastAPI App with Argon2id ====================

app_argon2id = FastAPI()

# In-memory user storage
argon2id_users_db = {}
argon2id_hasher = Argon2idHasher(config=ARGON2_PROFILE.RECOMMENDED)


@app_argon2id.post("/register")
async def register_argon2id(user: UserRegister):
    if user.username in argon2id_users_db:
        raise HTTPException(status_code=400, detail="User already exists")
    
    hashed_password = argon2id_hasher.password_hash(user.password)
    argon2id_users_db[user.username] = hashed_password
    
    return {"message": "User registered successfully"}


@app_argon2id.post("/login")
async def login_argon2id(user: UserLogin):
    if user.username not in argon2id_users_db:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    stored_hash = argon2id_users_db[user.username]
    
    if not argon2id_hasher.password_verify(stored_hash, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    return {"message": "Login successful"}


# ==================== FastAPI App with Bcrypt ====================

app_bcrypt = FastAPI()

# In-memory user storage
bcrypt_users_db = {}
bcrypt_hasher = BcryptHasher(bcrypt_rounds=BcryptRounds.LITE)  # LITE for faster tests


@app_bcrypt.post("/register")
async def register_bcrypt(user: UserRegister):
    if user.username in bcrypt_users_db:
        raise HTTPException(status_code=400, detail="User already exists")
    
    hashed_password = bcrypt_hasher.password_hash(user.password)
    bcrypt_users_db[user.username] = hashed_password
    
    return {"message": "User registered successfully"}


@app_bcrypt.post("/login")
async def login_bcrypt(user: UserLogin):
    if user.username not in bcrypt_users_db:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    stored_hash = bcrypt_users_db[user.username]
    
    try:
        bcrypt_hasher.password_verify(stored_hash, user.password)
    except BcryptVerificationError:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    return {"message": "Login successful"}


# ==================== FastAPI App with SHA HMAC ====================

app_hmac = FastAPI()

# Generate HMAC key
hmac_key = generate_symmetric_key(UsageType.SHA256_HMAC, rotation_interval_days=30)
hmac_config = SHAHMACConfig(key=hmac_key)
hmac_hasher = SHAHMACHasher(config=hmac_config)


@app_hmac.post("/sign")
async def sign_message(data: MessageSign):
    signature = hmac_hasher.hash(data.message)
    return {"message": data.message, "signature": signature}


@app_hmac.post("/verify")
async def verify_message(data: MessageVerify):
    is_valid = hmac_hasher.verify(data.message, data.signature)
    
    if not is_valid:
        raise HTTPException(status_code=400, detail="Invalid signature")
    
    return {"message": "Signature is valid", "valid": True}


# ==================== Tests ====================

class TestArgon2idFastAPIIntegration:
    """Argon2id FastAPI 통합 테스트"""
    
    def setup_method(self):
        """각 테스트 전에 사용자 DB 초기화"""
        argon2id_users_db.clear()
    
    def test_user_registration(self):
        """사용자 등록 테스트"""
        client = TestClient(app_argon2id)
        
        response = client.post("/register", json={
            "username": "testuser",
            "password": "SecurePassword123!"
        })
        
        assert response.status_code == 200
        assert response.json()["message"] == "User registered successfully"
        assert "testuser" in argon2id_users_db
    
    def test_duplicate_registration(self):
        """중복 사용자 등록 테스트"""
        client = TestClient(app_argon2id)
        
        # 첫 번째 등록
        client.post("/register", json={
            "username": "testuser",
            "password": "password123"
        })
        
        # 중복 등록 시도
        response = client.post("/register", json={
            "username": "testuser",
            "password": "password456"
        })
        
        assert response.status_code == 400
        assert "already exists" in response.json()["detail"]
    
    def test_successful_login(self):
        """성공적인 로그인 테스트"""
        client = TestClient(app_argon2id)
        
        # 사용자 등록
        client.post("/register", json={
            "username": "testuser",
            "password": "MyPassword123"
        })
        
        # 로그인
        response = client.post("/login", json={
            "username": "testuser",
            "password": "MyPassword123"
        })
        
        assert response.status_code == 200
        assert response.json()["message"] == "Login successful"
    
    def test_login_wrong_password(self):
        """잘못된 비밀번호로 로그인 테스트"""
        client = TestClient(app_argon2id)
        
        # 사용자 등록
        client.post("/register", json={
            "username": "testuser",
            "password": "CorrectPassword"
        })
        
        # 잘못된 비밀번호로 로그인
        response = client.post("/login", json={
            "username": "testuser",
            "password": "WrongPassword"
        })
        
        assert response.status_code == 401
        assert "Invalid credentials" in response.json()["detail"]
    
    def test_login_nonexistent_user(self):
        """존재하지 않는 사용자 로그인 테스트"""
        client = TestClient(app_argon2id)
        
        response = client.post("/login", json={
            "username": "nonexistent",
            "password": "password123"
        })
        
        assert response.status_code == 401
        assert "Invalid credentials" in response.json()["detail"]
    
    def test_unicode_password(self):
        """유니코드 비밀번호 테스트"""
        client = TestClient(app_argon2id)
        
        # 한글 비밀번호로 등록
        client.post("/register", json={
            "username": "koreanuser",
            "password": "한글비밀번호123!@#"
        })
        
        # 한글 비밀번호로 로그인
        response = client.post("/login", json={
            "username": "koreanuser",
            "password": "한글비밀번호123!@#"
        })
        
        assert response.status_code == 200


class TestBcryptFastAPIIntegration:
    """Bcrypt FastAPI 통합 테스트"""
    
    def setup_method(self):
        """각 테스트 전에 사용자 DB 초기화"""
        bcrypt_users_db.clear()
    
    def test_user_registration(self):
        """사용자 등록 테스트"""
        client = TestClient(app_bcrypt)
        
        response = client.post("/register", json={
            "username": "bcryptuser",
            "password": "BcryptPass123!"
        })
        
        assert response.status_code == 200
        assert response.json()["message"] == "User registered successfully"
        assert "bcryptuser" in bcrypt_users_db
    
    def test_successful_login(self):
        """성공적인 로그인 테스트"""
        client = TestClient(app_bcrypt)
        
        # 사용자 등록
        client.post("/register", json={
            "username": "bcryptuser",
            "password": "MyBcryptPass123"
        })
        
        # 로그인
        response = client.post("/login", json={
            "username": "bcryptuser",
            "password": "MyBcryptPass123"
        })
        
        assert response.status_code == 200
        assert response.json()["message"] == "Login successful"
    
    def test_login_wrong_password(self):
        """잘못된 비밀번호로 로그인 테스트"""
        client = TestClient(app_bcrypt)
        
        # 사용자 등록
        client.post("/register", json={
            "username": "bcryptuser",
            "password": "CorrectPassword"
        })
        
        # 잘못된 비밀번호로 로그인
        response = client.post("/login", json={
            "username": "bcryptuser",
            "password": "WrongPassword"
        })
        
        assert response.status_code == 401
        assert "Invalid credentials" in response.json()["detail"]
    
    def test_max_length_password(self):
        """최대 길이 비밀번호 테스트 (72 bytes)"""
        client = TestClient(app_bcrypt)
        
        # 72자의 비밀번호
        long_password = "a" * 72
        
        client.post("/register", json={
            "username": "longpassuser",
            "password": long_password
        })
        
        response = client.post("/login", json={
            "username": "longpassuser",
            "password": long_password
        })
        
        assert response.status_code == 200


class TestSHAHMACFastAPIIntegration:
    """SHA HMAC FastAPI 통합 테스트"""
    
    def test_sign_message(self):
        """메시지 서명 테스트"""
        client = TestClient(app_hmac)
        
        response = client.post("/sign", json={
            "message": "Hello, World!"
        })
        
        assert response.status_code == 200
        assert "message" in response.json()
        assert "signature" in response.json()
        assert response.json()["message"] == "Hello, World!"
        assert len(response.json()["signature"]) == 64  # SHA256 hex
    
    def test_verify_valid_signature(self):
        """유효한 서명 검증 테스트"""
        client = TestClient(app_hmac)
        
        # 메시지 서명
        sign_response = client.post("/sign", json={
            "message": "Test message"
        })
        signature = sign_response.json()["signature"]
        
        # 서명 검증
        verify_response = client.post("/verify", json={
            "message": "Test message",
            "signature": signature
        })
        
        assert verify_response.status_code == 200
        assert verify_response.json()["valid"] is True
    
    def test_verify_invalid_signature(self):
        """잘못된 서명 검증 테스트"""
        client = TestClient(app_hmac)
        
        response = client.post("/verify", json={
            "message": "Test message",
            "signature": "0" * 64
        })
        
        assert response.status_code == 400
        assert "Invalid signature" in response.json()["detail"]
    
    def test_verify_tampered_message(self):
        """변조된 메시지 검증 테스트"""
        client = TestClient(app_hmac)
        
        # 원본 메시지 서명
        sign_response = client.post("/sign", json={
            "message": "Original message"
        })
        signature = sign_response.json()["signature"]
        
        # 변조된 메시지로 검증 시도
        verify_response = client.post("/verify", json={
            "message": "Tampered message",
            "signature": signature
        })
        
        assert verify_response.status_code == 400
        assert "Invalid signature" in verify_response.json()["detail"]
    
    def test_sign_unicode_message(self):
        """유니코드 메시지 서명 테스트"""
        client = TestClient(app_hmac)
        
        response = client.post("/sign", json={
            "message": "안녕하세요 🔒"
        })
        
        assert response.status_code == 200
        assert "signature" in response.json()
    
    def test_verify_unicode_message(self):
        """유니코드 메시지 검증 테스트"""
        client = TestClient(app_hmac)
        
        # 유니코드 메시지 서명
        sign_response = client.post("/sign", json={
            "message": "한글 메시지 테스트"
        })
        signature = sign_response.json()["signature"]
        
        # 검증
        verify_response = client.post("/verify", json={
            "message": "한글 메시지 테스트",
            "signature": signature
        })
        
        assert verify_response.status_code == 200
        assert verify_response.json()["valid"] is True
    
    def test_sign_empty_message(self):
        """빈 메시지 서명 테스트"""
        client = TestClient(app_hmac)
        
        response = client.post("/sign", json={
            "message": ""
        })
        
        assert response.status_code == 200
        assert "signature" in response.json()
    
    def test_sign_large_message(self):
        """큰 메시지 서명 테스트"""
        client = TestClient(app_hmac)
        
        large_message = "x" * 10000
        
        response = client.post("/sign", json={
            "message": large_message
        })
        
        assert response.status_code == 200
        assert "signature" in response.json()


# ==================== FastAPI App with Lifespan & Key Rotation ====================

class TestLifespanWithKeyRotation:
    """Lifespan에서 키 로테이션을 사용하는 FastAPI 앱 테스트"""
    
    def test_hmac_with_key_rotation_lifespan(self):
        """HMAC 키 로테이션이 적용된 lifespan 테스트"""
        
        with tempfile.TemporaryDirectory() as tmpdir:
            key_file = os.path.join(tmpdir, "hmac_key.json")
            
            # Lifespan with key rotation
            @asynccontextmanager
            async def lifespan(app: FastAPI):
                # SHA256 HMAC 키 로테이터 초기화
                rotator = SymmetricKeyRotator(
                    usage_type=UsageType.SHA256_HMAC,
                    rotation_interval_days=30,
                    load_type=LoadType.FILE,
                    options=FileLoadOptions(file_path=key_file)
                )
                await rotator.init()
                
                # 앱 상태에 저장
                app.state.hmac_rotator = rotator
                app.state.hmac_hasher = SHAHMACHasher(
                    config=SHAHMACConfig(key=rotator.current_key)
                )
                
                yield
                
                # Cleanup
                rotator.stop_scheduler()
            
            # FastAPI 앱 생성
            app = FastAPI(lifespan=lifespan)
            
            @app.post("/sign")
            async def sign_message(data: MessageSign):
                hasher = app.state.hmac_hasher
                signature = hasher.hash(data.message)
                return {"message": data.message, "signature": signature}
            
            @app.post("/verify")
            async def verify_message(data: MessageVerify):
                hasher = app.state.hmac_hasher
                is_valid = hasher.verify(data.message, data.signature)
                
                if not is_valid:
                    raise HTTPException(status_code=400, detail="Invalid signature")
                
                return {"message": "Signature is valid", "valid": True}
            
            @app.get("/key-info")
            async def get_key_info():
                rotator = app.state.hmac_rotator
                return {
                    "kid": rotator.current_key.kid,
                    "created_at": rotator.current_key.created_at.isoformat(),
                    "expires_at": rotator.current_key.expires_at.isoformat(),
                    "usage_type": rotator.current_key.usage_type.name
                }
            
            # 테스트 실행
            with TestClient(app) as client:
                # 키 정보 확인
                key_info_response = client.get("/key-info")
                assert key_info_response.status_code == 200
                key_info = key_info_response.json()
                assert "kid" in key_info
                assert key_info["usage_type"] == "SHA256_HMAC"
                
                # 메시지 서명
                sign_response = client.post("/sign", json={
                    "message": "Test with key rotation"
                })
                assert sign_response.status_code == 200
                signature = sign_response.json()["signature"]
                
                # 서명 검증
                verify_response = client.post("/verify", json={
                    "message": "Test with key rotation",
                    "signature": signature
                })
                assert verify_response.status_code == 200
                assert verify_response.json()["valid"] is True
                
                # 키 파일이 생성되었는지 확인
                assert os.path.exists(key_file)
    
    def test_bcrypt_with_pepper_rotation_lifespan(self):
        """Pepper 로테이션이 적용된 Bcrypt lifespan 테스트"""
        
        with tempfile.TemporaryDirectory() as tmpdir:
            pepper_key_file = os.path.join(tmpdir, "pepper_key.json")
            
            # Lifespan with pepper rotation
            @asynccontextmanager
            async def lifespan(app: FastAPI):
                # Pepper 키 로테이터 초기화
                pepper_rotator = SymmetricKeyRotator(
                    usage_type=UsageType.PASSWORD_PEPPER,
                    rotation_interval_days=30,
                    load_type=LoadType.FILE,
                    options=FileLoadOptions(file_path=pepper_key_file)
                )
                await pepper_rotator.init()
                
                # Pepper를 16 bytes로 제한 (bcrypt의 72 bytes 제한 고려)
                pepper = pepper_rotator.current_key.key[:16].hex()
                
                # 앱 상태에 저장
                app.state.pepper_rotator = pepper_rotator
                app.state.bcrypt_hasher = BcryptHasher(
                    bcrypt_rounds=BcryptRounds.LITE,
                    pepper=pepper
                )
                app.state.users_db = {}
                
                yield
                
                # Cleanup
                pepper_rotator.stop_scheduler()
            
            # FastAPI 앱 생성
            app = FastAPI(lifespan=lifespan)
            
            @app.post("/register")
            async def register(user: UserRegister):
                if user.username in app.state.users_db:
                    raise HTTPException(status_code=400, detail="User already exists")
                
                hasher = app.state.bcrypt_hasher
                hashed_password = hasher.password_hash(user.password)
                app.state.users_db[user.username] = hashed_password
                
                return {"message": "User registered successfully"}
            
            @app.post("/login")
            async def login(user: UserLogin):
                if user.username not in app.state.users_db:
                    raise HTTPException(status_code=401, detail="Invalid credentials")
                
                stored_hash = app.state.users_db[user.username]
                hasher = app.state.bcrypt_hasher
                
                try:
                    hasher.password_verify(stored_hash, user.password)
                except BcryptVerificationError:
                    raise HTTPException(status_code=401, detail="Invalid credentials")
                
                return {"message": "Login successful"}
            
            @app.get("/pepper-info")
            async def get_pepper_info():
                rotator = app.state.pepper_rotator
                return {
                    "kid": rotator.current_key.kid,
                    "created_at": rotator.current_key.created_at.isoformat(),
                    "expires_at": rotator.current_key.expires_at.isoformat(),
                    "usage_type": rotator.current_key.usage_type.name
                }
            
            # 테스트 실행
            with TestClient(app) as client:
                # Pepper 정보 확인
                pepper_info_response = client.get("/pepper-info")
                assert pepper_info_response.status_code == 200
                pepper_info = pepper_info_response.json()
                assert pepper_info["usage_type"] == "PASSWORD_PEPPER"
                
                # 사용자 등록
                register_response = client.post("/register", json={
                    "username": "pepperuser",
                    "password": "SecurePassword123!"
                })
                assert register_response.status_code == 200
                
                # 로그인
                login_response = client.post("/login", json={
                    "username": "pepperuser",
                    "password": "SecurePassword123!"
                })
                assert login_response.status_code == 200
                
                # Pepper 키 파일이 생성되었는지 확인
                assert os.path.exists(pepper_key_file)
    
    def test_argon2id_with_pepper_rotation_lifespan(self):
        """Pepper 로테이션이 적용된 Argon2id lifespan 테스트"""
        
        with tempfile.TemporaryDirectory() as tmpdir:
            pepper_key_file = os.path.join(tmpdir, "argon2_pepper_key.json")
            
            # Lifespan with pepper rotation
            @asynccontextmanager
            async def lifespan(app: FastAPI):
                # Pepper 키 로테이터 초기화
                pepper_rotator = SymmetricKeyRotator(
                    usage_type=UsageType.PASSWORD_PEPPER,
                    rotation_interval_days=30,
                    load_type=LoadType.FILE,
                    options=FileLoadOptions(file_path=pepper_key_file)
                )
                await pepper_rotator.init()
                
                # Pepper를 문자열로 변환
                pepper = pepper_rotator.current_key.key.hex()
                
                # 앱 상태에 저장
                app.state.pepper_rotator = pepper_rotator
                app.state.argon2_hasher = Argon2idHasher(
                    config=ARGON2_PROFILE.RECOMMENDED,
                    pepper=pepper
                )
                app.state.users_db = {}
                
                yield
                
                # Cleanup
                pepper_rotator.stop_scheduler()
            
            # FastAPI 앱 생성
            app = FastAPI(lifespan=lifespan)
            
            @app.post("/register")
            async def register(user: UserRegister):
                if user.username in app.state.users_db:
                    raise HTTPException(status_code=400, detail="User already exists")
                
                hasher = app.state.argon2_hasher
                hashed_password = hasher.password_hash(user.password)
                app.state.users_db[user.username] = hashed_password
                
                return {"message": "User registered successfully"}
            
            @app.post("/login")
            async def login(user: UserLogin):
                if user.username not in app.state.users_db:
                    raise HTTPException(status_code=401, detail="Invalid credentials")
                
                stored_hash = app.state.users_db[user.username]
                hasher = app.state.argon2_hasher
                
                if not hasher.password_verify(stored_hash, user.password):
                    raise HTTPException(status_code=401, detail="Invalid credentials")
                
                return {"message": "Login successful"}
            
            # 테스트 실행
            with TestClient(app) as client:
                # 사용자 등록
                register_response = client.post("/register", json={
                    "username": "argon2user",
                    "password": "VerySecurePassword123!"
                })
                assert register_response.status_code == 200
                
                # 로그인
                login_response = client.post("/login", json={
                    "username": "argon2user",
                    "password": "VerySecurePassword123!"
                })
                assert login_response.status_code == 200
                
                # Pepper 키 파일이 생성되었는지 확인
                assert os.path.exists(pepper_key_file)
    
    def test_multiple_key_rotators_in_lifespan(self):
        """여러 키 로테이터를 사용하는 lifespan 테스트"""
        
        with tempfile.TemporaryDirectory() as tmpdir:
            hmac_key_file = os.path.join(tmpdir, "hmac_key.json")
            pepper_key_file = os.path.join(tmpdir, "pepper_key.json")
            
            # Lifespan with multiple rotators
            @asynccontextmanager
            async def lifespan(app: FastAPI):
                # HMAC 키 로테이터
                hmac_rotator = SymmetricKeyRotator(
                    usage_type=UsageType.SHA256_HMAC,
                    rotation_interval_days=30,
                    load_type=LoadType.FILE,
                    options=FileLoadOptions(file_path=hmac_key_file)
                )
                await hmac_rotator.init()
                
                # Pepper 키 로테이터
                pepper_rotator = SymmetricKeyRotator(
                    usage_type=UsageType.PASSWORD_PEPPER,
                    rotation_interval_days=30,
                    load_type=LoadType.FILE,
                    options=FileLoadOptions(file_path=pepper_key_file)
                )
                await pepper_rotator.init()
                
                # 앱 상태에 저장
                app.state.hmac_rotator = hmac_rotator
                app.state.pepper_rotator = pepper_rotator
                app.state.hmac_hasher = SHAHMACHasher(
                    config=SHAHMACConfig(key=hmac_rotator.current_key)
                )
                app.state.bcrypt_hasher = BcryptHasher(
                    bcrypt_rounds=BcryptRounds.LITE,
                    pepper=pepper_rotator.current_key.key[:16].hex()  # 16 bytes로 제한
                )
                app.state.users_db = {}
                
                yield
                
                # Cleanup
                hmac_rotator.stop_scheduler()
                pepper_rotator.stop_scheduler()
            
            # FastAPI 앱 생성
            app = FastAPI(lifespan=lifespan)
            
            @app.post("/register")
            async def register(user: UserRegister):
                if user.username in app.state.users_db:
                    raise HTTPException(status_code=400, detail="User already exists")
                
                hasher = app.state.bcrypt_hasher
                hashed_password = hasher.password_hash(user.password)
                app.state.users_db[user.username] = hashed_password
                
                return {"message": "User registered successfully"}
            
            @app.post("/login")
            async def login(user: UserLogin):
                if user.username not in app.state.users_db:
                    raise HTTPException(status_code=401, detail="Invalid credentials")
                
                stored_hash = app.state.users_db[user.username]
                hasher = app.state.bcrypt_hasher
                
                try:
                    hasher.password_verify(stored_hash, user.password)
                except BcryptVerificationError:
                    raise HTTPException(status_code=401, detail="Invalid credentials")
                
                return {"message": "Login successful"}
            
            @app.post("/sign")
            async def sign_message(data: MessageSign):
                hasher = app.state.hmac_hasher
                signature = hasher.hash(data.message)
                return {"message": data.message, "signature": signature}
            
            @app.get("/system-info")
            async def get_system_info():
                return {
                    "hmac_key": {
                        "kid": app.state.hmac_rotator.current_key.kid,
                        "usage_type": app.state.hmac_rotator.current_key.usage_type.name
                    },
                    "pepper_key": {
                        "kid": app.state.pepper_rotator.current_key.kid,
                        "usage_type": app.state.pepper_rotator.current_key.usage_type.name
                    }
                }
            
            # 테스트 실행
            with TestClient(app) as client:
                # 시스템 정보 확인
                system_info_response = client.get("/system-info")
                assert system_info_response.status_code == 200
                system_info = system_info_response.json()
                assert system_info["hmac_key"]["usage_type"] == "SHA256_HMAC"
                assert system_info["pepper_key"]["usage_type"] == "PASSWORD_PEPPER"
                
                # 사용자 등록 (Bcrypt with Pepper)
                register_response = client.post("/register", json={
                    "username": "multiuser",
                    "password": "MultiKeyPassword123!"
                })
                assert register_response.status_code == 200
                
                # 로그인
                login_response = client.post("/login", json={
                    "username": "multiuser",
                    "password": "MultiKeyPassword123!"
                })
                assert login_response.status_code == 200
                
                # 메시지 서명 (HMAC)
                sign_response = client.post("/sign", json={
                    "message": "Test message with multiple keys"
                })
                assert sign_response.status_code == 200
                assert "signature" in sign_response.json()
                
                # 키 파일들이 생성되었는지 확인
                assert os.path.exists(hmac_key_file)
                assert os.path.exists(pepper_key_file)
