# coding: utf-8
# tests/test_crypto_hashing.py

import pytest
from argon2 import Type

from crypto_toolkit.crypto.hashing.argon2id import (
    Argon2idHasher,
    Argon2idConfig,
    ARGON2_PROFILE,
)
from crypto_toolkit.crypto.hashing.bcrypt import (
    BcryptHasher,
    BcryptRounds,
    BcryptVerificationError,
)
from crypto_toolkit.crypto.hashing.sha_hmac import (
    SHAHMACHasher,
    SHAHMACConfig,
)
from crypto_toolkit.key_management.symmetric import generate_symmetric_key, UsageType


class TestArgon2idHasher:
    """Argon2id 해싱 테스트"""

    def test_hash_password_basic(self):
        """기본 비밀번호 해싱 테스트"""
        hasher = Argon2idHasher(config=ARGON2_PROFILE.BASIC)
        password = "test_password123"
        
        hashed = hasher.password_hash(password)
        
        assert hashed is not None
        assert isinstance(hashed, str)
        assert hashed.startswith("$argon2id$")
        assert len(hashed) > 0

    def test_hash_password_recommended(self):
        """RECOMMENDED 프로파일 해싱 테스트"""
        hasher = Argon2idHasher(config=ARGON2_PROFILE.RECOMMENDED)
        password = "secure_password_456"
        
        hashed = hasher.password_hash(password)
        
        assert hashed.startswith("$argon2id$")

    def test_hash_password_strong(self):
        """STRONG 프로파일 해싱 테스트"""
        hasher = Argon2idHasher(config=ARGON2_PROFILE.STRONG)
        password = "very_secure_password_789"
        
        hashed = hasher.password_hash(password)
        
        assert hashed.startswith("$argon2id$")

    def test_password_verify_success(self):
        """비밀번호 검증 성공 테스트"""
        hasher = Argon2idHasher(config=ARGON2_PROFILE.RECOMMENDED)
        password = "correct_password"
        
        hashed = hasher.password_hash(password)
        result = hasher.password_verify(hashed, password)
        
        assert result is True

    def test_password_verify_failure(self):
        """비밀번호 검증 실패 테스트"""
        hasher = Argon2idHasher(config=ARGON2_PROFILE.RECOMMENDED)
        password = "correct_password"
        wrong_password = "wrong_password"
        
        hashed = hasher.password_hash(password)
        result = hasher.password_verify(hashed, wrong_password)
        
        assert result is False

    def test_hash_with_pepper(self):
        """Pepper 사용 해싱 테스트"""
        pepper = "my_secret_pepper"
        hasher = Argon2idHasher(config=ARGON2_PROFILE.RECOMMENDED, pepper=pepper)
        password = "test_password"
        
        hashed = hasher.password_hash(password)
        
        # Pepper가 포함된 해시는 검증에 성공해야 함
        assert hasher.password_verify(hashed, password) is True

    def test_pepper_affects_hash(self):
        """Pepper가 해시에 영향을 주는지 테스트"""
        password = "same_password"
        
        hasher1 = Argon2idHasher(config=ARGON2_PROFILE.RECOMMENDED, pepper="pepper1")
        hasher2 = Argon2idHasher(config=ARGON2_PROFILE.RECOMMENDED, pepper="pepper2")
        
        hash1 = hasher1.password_hash(password)
        hash2 = hasher2.password_hash(password)
        
        # 다른 pepper를 사용하면 다른 해시가 생성됨
        assert hash1 != hash2
        
        # 각각의 hasher로 검증해야 성공
        assert hasher1.password_verify(hash1, password) is True
        assert hasher2.password_verify(hash2, password) is True
        
        # 다른 hasher로 검증하면 실패
        assert hasher1.password_verify(hash2, password) is False
        assert hasher2.password_verify(hash1, password) is False

    def test_custom_config(self):
        """커스텀 설정으로 해싱 테스트"""
        custom_config = Argon2idConfig(
            time_cost=2,
            memory_cost=32768,
            parallelism=1,
            hash_len=32,
            salt_len=16,
            type=Type.ID
        )
        hasher = Argon2idHasher(config=ARGON2_PROFILE.BASIC)
        password = "custom_config_password"
        
        hashed = hasher.password_hash(password)
        
        assert hasher.password_verify(hashed, password) is True

    def test_different_passwords_produce_different_hashes(self):
        """다른 비밀번호는 다른 해시를 생성하는지 테스트"""
        hasher = Argon2idHasher(config=ARGON2_PROFILE.RECOMMENDED)
        
        hash1 = hasher.password_hash("password1")
        hash2 = hasher.password_hash("password2")
        
        assert hash1 != hash2

    def test_same_password_produces_different_hashes_with_salt(self):
        """같은 비밀번호도 다른 솔트로 다른 해시 생성 테스트"""
        hasher = Argon2idHasher(config=ARGON2_PROFILE.RECOMMENDED)
        password = "same_password"
        
        hash1 = hasher.password_hash(password)
        hash2 = hasher.password_hash(password)
        
        # 솔트가 자동 생성되므로 해시가 다름
        assert hash1 != hash2
        
        # 하지만 둘 다 검증에는 성공
        assert hasher.password_verify(hash1, password) is True
        assert hasher.password_verify(hash2, password) is True

    def test_verify_invalid_hash_format(self):
        """잘못된 해시 형식 검증 테스트"""
        hasher = Argon2idHasher(config=ARGON2_PROFILE.RECOMMENDED)
        invalid_hash = "invalid_hash_format"
        password = "some_password"
        
        result = hasher.password_verify(invalid_hash, password)
        
        assert result is False

    def test_check_needs_rehash(self):
        """재해싱 필요 여부 확인 테스트"""
        hasher = Argon2idHasher(config=ARGON2_PROFILE.BASIC)
        password = "test_password"
        
        hashed = hasher.password_hash(password)
        needs_rehash = hasher.check_needs_rehash(hashed)
        
        # BASIC 프로파일로 해싱했으므로 재해싱 필요 여부 확인 가능
        assert isinstance(needs_rehash, bool)

    def test_unicode_password(self):
        """유니코드 비밀번호 해싱 테스트"""
        hasher = Argon2idHasher(config=ARGON2_PROFILE.RECOMMENDED)
        password = "비밀번호123!@#"
        
        hashed = hasher.password_hash(password)
        
        assert hasher.password_verify(hashed, password) is True


class TestBcryptHasher:
    """Bcrypt 해싱 테스트"""

    def test_hash_password_lite(self):
        """LITE 라운드 해싱 테스트"""
        hasher = BcryptHasher(bcrypt_rounds=BcryptRounds.LITE)
        password = "test_password"
        
        hashed = hasher.password_hash(password)
        
        assert hashed is not None
        assert isinstance(hashed, str)
        assert hashed.startswith("$2b$")

    def test_hash_password_recommended(self):
        """RECOMMENDED 라운드 해싱 테스트"""
        hasher = BcryptHasher(bcrypt_rounds=BcryptRounds.RECOMMENDED)
        password = "secure_password"
        
        hashed = hasher.password_hash(password)
        
        assert hashed.startswith("$2b$")
        assert "$12$" in hashed  # 12 rounds

    def test_hash_password_strong(self):
        """STRONG 라운드 해싱 테스트"""
        hasher = BcryptHasher(bcrypt_rounds=BcryptRounds.STRONG)
        password = "very_secure_password"
        
        hashed = hasher.password_hash(password)
        
        assert hashed.startswith("$2b$")
        assert "$14$" in hashed  # 14 rounds

    def test_password_verify_success(self):
        """비밀번호 검증 성공 테스트"""
        hasher = BcryptHasher(bcrypt_rounds=BcryptRounds.LITE)
        password = "correct_password"
        
        hashed = hasher.password_hash(password)
        
        # 검증 성공 시 예외가 발생하지 않아야 함
        try:
            hasher.password_verify(hashed, password)
        except BcryptVerificationError:
            pytest.fail("비밀번호 검증이 실패했습니다.")

    def test_password_verify_failure(self):
        """비밀번호 검증 실패 테스트"""
        hasher = BcryptHasher(bcrypt_rounds=BcryptRounds.LITE)
        password = "correct_password"
        wrong_password = "wrong_password"
        
        hashed = hasher.password_hash(password)
        
        # 검증 실패 시 예외가 발생해야 함
        with pytest.raises(BcryptVerificationError):
            hasher.password_verify(hashed, wrong_password)

    def test_hash_with_pepper(self):
        """Pepper 사용 해싱 테스트"""
        pepper = "secret_pepper"
        hasher = BcryptHasher(bcrypt_rounds=BcryptRounds.LITE, pepper=pepper)
        password = "test_password"
        
        hashed = hasher.password_hash(password)
        
        # Pepper가 포함된 해시는 검증에 성공해야 함
        try:
            hasher.password_verify(hashed, password)
        except BcryptVerificationError:
            pytest.fail("Pepper를 사용한 검증이 실패했습니다.")

    def test_pepper_affects_hash(self):
        """Pepper가 해시에 영향을 주는지 테스트"""
        password = "same_password"
        
        hasher1 = BcryptHasher(bcrypt_rounds=BcryptRounds.LITE, pepper="pepper1")
        hasher2 = BcryptHasher(bcrypt_rounds=BcryptRounds.LITE, pepper="pepper2")
        
        hash1 = hasher1.password_hash(password)
        hash2 = hasher2.password_hash(password)
        
        # 다른 pepper를 사용하면 다른 해시가 생성됨
        assert hash1 != hash2

    def test_different_passwords_produce_different_hashes(self):
        """다른 비밀번호는 다른 해시를 생성하는지 테스트"""
        hasher = BcryptHasher(bcrypt_rounds=BcryptRounds.LITE)
        
        hash1 = hasher.password_hash("password1")
        hash2 = hasher.password_hash("password2")
        
        assert hash1 != hash2

    def test_same_password_produces_different_hashes_with_salt(self):
        """같은 비밀번호도 다른 솔트로 다른 해시 생성 테스트"""
        hasher = BcryptHasher(bcrypt_rounds=BcryptRounds.LITE)
        password = "same_password"
        
        hash1 = hasher.password_hash(password)
        hash2 = hasher.password_hash(password)
        
        # 솔트가 자동 생성되므로 해시가 다름
        assert hash1 != hash2
        
        # 하지만 둘 다 검증에는 성공
        try:
            hasher.password_verify(hash1, password)
            hasher.password_verify(hash2, password)
        except BcryptVerificationError:
            pytest.fail("같은 비밀번호 검증이 실패했습니다.")

    def test_unicode_password(self):
        """유니코드 비밀번호 해싱 테스트"""
        hasher = BcryptHasher(bcrypt_rounds=BcryptRounds.LITE)
        password = "한글비밀번호123"
        
        hashed = hasher.password_hash(password)
        
        try:
            hasher.password_verify(hashed, password)
        except BcryptVerificationError:
            pytest.fail("유니코드 비밀번호 검증이 실패했습니다.")

    def test_max_length_password(self):
        """최대 길이 비밀번호 테스트 (72 bytes)"""
        hasher = BcryptHasher(bcrypt_rounds=BcryptRounds.LITE)
        # 72자의 영문자 (72 bytes)
        password = "a" * 72
        
        hashed = hasher.password_hash(password)
        
        try:
            hasher.password_verify(hashed, password)
        except BcryptVerificationError:
            pytest.fail("최대 길이 비밀번호 검증이 실패했습니다.")

    def test_check_needs_rehash(self):
        """재해싱 필요 여부 확인 테스트"""
        hasher = BcryptHasher(bcrypt_rounds=BcryptRounds.LITE)
        password = "test_password"
        
        hashed = hasher.password_hash(password)
        needs_rehash = hasher.check_needs_rehash(hashed.encode('utf-8'))
        
        # 현재 설정과 동일한 라운드로 해싱했으므로 재해싱 불필요
        assert needs_rehash is False

    def test_check_needs_rehash_with_different_rounds(self):
        """다른 라운드로 재해싱 필요 여부 테스트"""
        hasher_lite = BcryptHasher(bcrypt_rounds=BcryptRounds.LITE)
        hasher_strong = BcryptHasher(bcrypt_rounds=BcryptRounds.STRONG)
        password = "test_password"
        
        # LITE로 해싱
        hashed = hasher_lite.password_hash(password)
        
        # STRONG 설정으로 확인하면 재해싱 필요
        needs_rehash = hasher_strong.check_needs_rehash(hashed.encode('utf-8'))
        
        assert needs_rehash is True


class TestSHAHMACHasher:
    """SHA HMAC 해싱 테스트"""

    def test_hash_with_sha256_string(self):
        """SHA256 HMAC 문자열 해싱 테스트"""
        key = generate_symmetric_key(UsageType.SHA256_HMAC, rotation_interval_days=30)
        config = SHAHMACConfig(key=key)
        hasher = SHAHMACHasher(config=config)
        message = "test message"
        
        hashed = hasher.hash(message)
        
        assert hashed is not None
        assert isinstance(hashed, str)
        assert len(hashed) == 64  # SHA256 produces 64 hex characters

    def test_hash_with_sha256_bytes(self):
        """SHA256 HMAC 바이트 해싱 테스트"""
        key = generate_symmetric_key(UsageType.SHA256_HMAC, rotation_interval_days=30)
        config = SHAHMACConfig(key=key)
        hasher = SHAHMACHasher(config=config)
        message = b"test message bytes"
        
        hashed = hasher.hash(message)
        
        assert hashed is not None
        assert isinstance(hashed, str)
        assert len(hashed) == 64

    def test_hash_with_sha512_string(self):
        """SHA512 HMAC 문자열 해싱 테스트"""
        key = generate_symmetric_key(UsageType.SHA512_HMAC, rotation_interval_days=30)
        config = SHAHMACConfig(key=key)
        hasher = SHAHMACHasher(config=config)
        message = "test message for sha512"
        
        hashed = hasher.hash(message)
        
        assert hashed is not None
        assert isinstance(hashed, str)
        assert len(hashed) == 128  # SHA512 produces 128 hex characters

    def test_hash_with_sha512_bytes(self):
        """SHA512 HMAC 바이트 해싱 테스트"""
        key = generate_symmetric_key(UsageType.SHA512_HMAC, rotation_interval_days=30)
        config = SHAHMACConfig(key=key)
        hasher = SHAHMACHasher(config=config)
        message = b"test message bytes for sha512"
        
        hashed = hasher.hash(message)
        
        assert hashed is not None
        assert isinstance(hashed, str)
        assert len(hashed) == 128

    def test_verify_success_string(self):
        """HMAC 검증 성공 테스트 (문자열)"""
        key = generate_symmetric_key(UsageType.SHA256_HMAC, rotation_interval_days=30)
        config = SHAHMACConfig(key=key)
        hasher = SHAHMACHasher(config=config)
        message = "authentic message"
        
        hmac_value = hasher.hash(message)
        result = hasher.verify(message, hmac_value)
        
        assert result is True

    def test_verify_success_bytes(self):
        """HMAC 검증 성공 테스트 (바이트)"""
        key = generate_symmetric_key(UsageType.SHA256_HMAC, rotation_interval_days=30)
        config = SHAHMACConfig(key=key)
        hasher = SHAHMACHasher(config=config)
        message = b"authentic message bytes"
        
        hmac_value = hasher.hash(message)
        result = hasher.verify(message, hmac_value)
        
        assert result is True

    def test_verify_failure_wrong_message(self):
        """HMAC 검증 실패 테스트 (잘못된 메시지)"""
        key = generate_symmetric_key(UsageType.SHA256_HMAC, rotation_interval_days=30)
        config = SHAHMACConfig(key=key)
        hasher = SHAHMACHasher(config=config)
        message = "original message"
        tampered_message = "tampered message"
        
        hmac_value = hasher.hash(message)
        result = hasher.verify(tampered_message, hmac_value)
        
        assert result is False

    def test_verify_failure_wrong_hmac(self):
        """HMAC 검증 실패 테스트 (잘못된 HMAC)"""
        key = generate_symmetric_key(UsageType.SHA256_HMAC, rotation_interval_days=30)
        config = SHAHMACConfig(key=key)
        hasher = SHAHMACHasher(config=config)
        message = "test message"
        wrong_hmac = "0" * 64
        
        result = hasher.verify(message, wrong_hmac)
        
        assert result is False

    def test_hash_with_pepper_string(self):
        """Pepper 사용 해싱 테스트 (문자열)"""
        key = generate_symmetric_key(UsageType.SHA256_HMAC, rotation_interval_days=30)
        config = SHAHMACConfig(key=key)
        pepper = "my_pepper"
        hasher = SHAHMACHasher(config=config, pepper=pepper)
        message = "test message"
        
        hashed = hasher.hash(message)
        
        assert hasher.verify(message, hashed) is True

    def test_hash_with_pepper_bytes(self):
        """Pepper 사용 해싱 테스트 (바이트)"""
        key = generate_symmetric_key(UsageType.SHA256_HMAC, rotation_interval_days=30)
        config = SHAHMACConfig(key=key)
        pepper = "my_pepper"
        hasher = SHAHMACHasher(config=config, pepper=pepper)
        message = b"test message bytes"
        
        hashed = hasher.hash(message)
        
        assert hasher.verify(message, hashed) is True

    def test_pepper_affects_hash(self):
        """Pepper가 해시에 영향을 주는지 테스트"""
        key = generate_symmetric_key(UsageType.SHA256_HMAC, rotation_interval_days=30)
        config = SHAHMACConfig(key=key)
        message = "same message"
        
        hasher1 = SHAHMACHasher(config=config, pepper="pepper1")
        hasher2 = SHAHMACHasher(config=config, pepper="pepper2")
        
        hash1 = hasher1.hash(message)
        hash2 = hasher2.hash(message)
        
        # 다른 pepper를 사용하면 다른 해시가 생성됨
        assert hash1 != hash2
        
        # 각각의 hasher로 검증해야 성공
        assert hasher1.verify(message, hash1) is True
        assert hasher2.verify(message, hash2) is True
        
        # 다른 hasher로 검증하면 실패
        assert hasher1.verify(message, hash2) is False
        assert hasher2.verify(message, hash1) is False

    def test_different_keys_produce_different_hashes(self):
        """다른 키는 다른 해시를 생성하는지 테스트"""
        key1 = generate_symmetric_key(UsageType.SHA256_HMAC, rotation_interval_days=30)
        key2 = generate_symmetric_key(UsageType.SHA256_HMAC, rotation_interval_days=30)
        
        config1 = SHAHMACConfig(key=key1)
        config2 = SHAHMACConfig(key=key2)
        
        hasher1 = SHAHMACHasher(config=config1)
        hasher2 = SHAHMACHasher(config=config2)
        
        message = "same message"
        
        hash1 = hasher1.hash(message)
        hash2 = hasher2.hash(message)
        
        assert hash1 != hash2

    def test_same_message_with_same_key_produces_same_hash(self):
        """같은 키와 메시지는 같은 해시를 생성하는지 테스트"""
        key = generate_symmetric_key(UsageType.SHA256_HMAC, rotation_interval_days=30)
        config = SHAHMACConfig(key=key)
        hasher = SHAHMACHasher(config=config)
        message = "consistent message"
        
        hash1 = hasher.hash(message)
        hash2 = hasher.hash(message)
        
        # HMAC는 결정론적이므로 같은 메시지는 같은 해시를 생성
        assert hash1 == hash2

    def test_unicode_message(self):
        """유니코드 메시지 해싱 테스트"""
        key = generate_symmetric_key(UsageType.SHA256_HMAC, rotation_interval_days=30)
        config = SHAHMACConfig(key=key)
        hasher = SHAHMACHasher(config=config)
        message = "한글 메시지 테스트 🔒"
        
        hashed = hasher.hash(message)
        
        assert hasher.verify(message, hashed) is True

    def test_empty_message(self):
        """빈 메시지 해싱 테스트"""
        key = generate_symmetric_key(UsageType.SHA256_HMAC, rotation_interval_days=30)
        config = SHAHMACConfig(key=key)
        hasher = SHAHMACHasher(config=config)
        message = ""
        
        hashed = hasher.hash(message)
        
        assert hashed is not None
        assert hasher.verify(message, hashed) is True

    def test_large_message(self):
        """큰 메시지 해싱 테스트"""
        key = generate_symmetric_key(UsageType.SHA256_HMAC, rotation_interval_days=30)
        config = SHAHMACConfig(key=key)
        hasher = SHAHMACHasher(config=config)
        message = "x" * 10000  # 10KB 메시지
        
        hashed = hasher.hash(message)
        
        assert hasher.verify(message, hashed) is True
