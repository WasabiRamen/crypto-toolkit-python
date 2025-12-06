# coding: utf-8
# tests/test_key_management_symmetric.py

import pytest
import asyncio
import json
import os
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

from crypto_toolkit.key_management.symmetric import (
    SymmetricKey,
    SymmetricKeyRotator,
    UsageType,
    LoadType,
    FileLoadOptions,
    generate_symmetric_key,
    load_symmetric_key,
    save_symmetric_key,
)


class TestSymmetricKeyGeneration:
    """대칭 키 생성 테스트"""

    def test_generate_aes128_key(self):
        """AES128 키 생성 테스트"""
        key = generate_symmetric_key(UsageType.AES128, rotation_interval_days=30)
        
        assert key.kid is not None
        assert len(key.kid) > 0
        assert len(key.key) == 16  # 128 bits = 16 bytes
        assert key.usage_type == UsageType.AES128
        assert key.created_at is not None
        assert key.expires_at is not None
        assert key.expires_at > key.created_at
        assert (key.expires_at - key.created_at).days == 30

    def test_generate_aes256_key(self):
        """AES256 키 생성 테스트"""
        key = generate_symmetric_key(UsageType.AES256, rotation_interval_days=90)
        
        assert len(key.key) == 32  # 256 bits = 32 bytes
        assert key.usage_type == UsageType.AES256
        assert (key.expires_at - key.created_at).days == 90

    def test_generate_sha256_hmac_key(self):
        """SHA256_HMAC 키 생성 테스트"""
        key = generate_symmetric_key(UsageType.SHA256_HMAC, rotation_interval_days=60)
        
        assert len(key.key) == 32  # 256 bits = 32 bytes
        assert key.usage_type == UsageType.SHA256_HMAC
        assert (key.expires_at - key.created_at).days == 60

    def test_generate_sha512_hmac_key(self):
        """SHA512_HMAC 키 생성 테스트"""
        key = generate_symmetric_key(UsageType.SHA512_HMAC, rotation_interval_days=120)
        
        assert len(key.key) == 64  # 512 bits = 64 bytes
        assert key.usage_type == UsageType.SHA512_HMAC
        assert (key.expires_at - key.created_at).days == 120

    def test_keys_are_unique(self):
        """생성된 키가 고유한지 테스트"""
        key1 = generate_symmetric_key(UsageType.AES256, rotation_interval_days=30)
        key2 = generate_symmetric_key(UsageType.AES256, rotation_interval_days=30)
        
        assert key1.key != key2.key
        assert key1.kid != key2.kid

    def test_key_getitem_access(self):
        """SymmetricKey의 __getitem__ 접근 테스트"""
        key = generate_symmetric_key(UsageType.AES256, rotation_interval_days=30)
        
        assert key['kid'] == key.kid
        assert key['key'] == key.key
        assert key['usage_type'] == key.usage_type
        assert key['created_at'] == key.created_at
        assert key['expires_at'] == key.expires_at


class TestSymmetricKeySaveLoad:
    """대칭 키 저장 및 로드 테스트"""

    @pytest.mark.asyncio
    async def test_save_and_load_key(self):
        """키 저장 후 로드 테스트"""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "test_key.json")
            options = FileLoadOptions(file_path=file_path)
            
            # 키 생성 및 저장
            original_key = generate_symmetric_key(UsageType.AES256, rotation_interval_days=30)
            await save_symmetric_key(original_key, LoadType.FILE, options=options)
            
            # 파일 존재 확인
            assert os.path.exists(file_path)
            
            # 키 로드
            loaded_key = await load_symmetric_key(
                UsageType.AES256,
                LoadType.FILE,
                rotation_interval_days=30,
                options=options
            )
            
            # 검증
            assert loaded_key.kid == original_key.kid
            assert loaded_key.key == original_key.key
            assert loaded_key.usage_type == original_key.usage_type
            assert loaded_key.created_at == original_key.created_at
            assert loaded_key.expires_at == original_key.expires_at

    @pytest.mark.asyncio
    async def test_load_creates_new_key_if_not_exists(self):
        """파일이 없으면 새 키 생성 테스트"""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "new_key.json")
            options = FileLoadOptions(file_path=file_path)
            
            # 파일이 없는 상태에서 로드
            key = await load_symmetric_key(
                UsageType.AES256,
                LoadType.FILE,
                rotation_interval_days=30,
                options=options
            )
            
            # 새 키가 생성되었는지 확인
            assert key.kid is not None
            assert len(key.key) == 32
            assert os.path.exists(file_path)

    @pytest.mark.asyncio
    async def test_load_creates_directory_if_not_exists(self):
        """디렉토리가 없으면 생성 테스트"""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "subdir", "test_key.json")
            options = FileLoadOptions(file_path=file_path)
            
            # 디렉토리가 없는 상태에서 로드
            key = await load_symmetric_key(
                UsageType.AES256,
                LoadType.FILE,
                rotation_interval_days=30,
                options=options
            )
            
            assert os.path.exists(file_path)
            assert os.path.exists(os.path.dirname(file_path))

    @pytest.mark.asyncio
    async def test_save_key_validation(self):
        """키 저장 시 검증 테스트"""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "test_key.json")
            options = FileLoadOptions(file_path=file_path)
            key = generate_symmetric_key(UsageType.AES256, rotation_interval_days=30)
            
            await save_symmetric_key(key, LoadType.FILE, options=options)
            
            # 저장된 JSON 검증
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            assert 'kid' in data
            assert 'key' in data
            assert 'usage_type' in data
            assert 'created_at' in data
            assert 'expires_at' in data
            assert data['usage_type'] == 'AES256'

    @pytest.mark.asyncio
    async def test_load_with_invalid_json(self):
        """잘못된 JSON 파일 로드 시 에러 테스트"""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "invalid.json")
            options = FileLoadOptions(file_path=file_path)
            
            # 잘못된 JSON 작성
            with open(file_path, 'w') as f:
                f.write("{ invalid json }")
            
            with pytest.raises(ValueError, match="Invalid JSON format"):
                await load_symmetric_key(
                    UsageType.AES256,
                    LoadType.FILE,
                    rotation_interval_days=30,
                    options=options
                )

    @pytest.mark.asyncio
    async def test_load_with_missing_fields(self):
        """필수 필드가 없는 파일 로드 시 에러 테스트"""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "incomplete.json")
            options = FileLoadOptions(file_path=file_path)
            
            # 불완전한 데이터 작성
            with open(file_path, 'w') as f:
                json.dump({"kid": "test"}, f)
            
            with pytest.raises(ValueError, match="Invalid key data"):
                await load_symmetric_key(
                    UsageType.AES256,
                    LoadType.FILE,
                    rotation_interval_days=30,
                    options=options
                )

    @pytest.mark.asyncio
    async def test_save_invalid_file_path(self):
        """잘못된 파일 경로로 저장 시 에러 테스트"""
        options = FileLoadOptions(file_path="invalid_path.txt")
        key = generate_symmetric_key(UsageType.AES256, rotation_interval_days=30)
        
        with pytest.raises(ValueError, match="must point to a .json file"):
            await save_symmetric_key(key, LoadType.FILE, options=options)

    @pytest.mark.asyncio
    async def test_load_invalid_file_path(self):
        """잘못된 파일 경로로 로드 시 에러 테스트"""
        options = FileLoadOptions(file_path="invalid_path.txt")
        
        with pytest.raises(ValueError, match="must point to a .json file"):
            await load_symmetric_key(
                UsageType.AES256,
                LoadType.FILE,
                rotation_interval_days=30,
                options=options
            )

    @pytest.mark.asyncio
    async def test_invalid_load_type(self):
        """잘못된 LoadType 사용 시 에러 테스트"""
        with pytest.raises(ValueError, match="must be an instance of LoadType"):
            await load_symmetric_key(
                UsageType.AES256,
                "INVALID",  # type: ignore
                rotation_interval_days=30,
                options=None
            )

    @pytest.mark.asyncio
    async def test_missing_options_for_file_load_type(self):
        """FILE LoadType인데 options 없으면 에러 테스트"""
        with pytest.raises(TypeError, match="must be a FileLoadOptions instance"):
            await load_symmetric_key(
                UsageType.AES256,
                LoadType.FILE,
                rotation_interval_days=30,
                options=None
            )

    @pytest.mark.asyncio
    async def test_timezone_handling(self):
        """타임존 처리 테스트"""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "test_key.json")
            options = FileLoadOptions(file_path=file_path)
            
            # 키 생성 및 저장
            original_key = generate_symmetric_key(UsageType.AES256, rotation_interval_days=30)
            await save_symmetric_key(original_key, LoadType.FILE, options=options)
            
            # 키 로드
            loaded_key = await load_symmetric_key(
                UsageType.AES256,
                LoadType.FILE,
                rotation_interval_days=30,
                options=options
            )
            
            # 타임존 확인
            assert loaded_key.created_at.tzinfo is not None
            assert loaded_key.expires_at.tzinfo is not None
            assert loaded_key.created_at.tzinfo == timezone.utc
            assert loaded_key.expires_at.tzinfo == timezone.utc


class TestSymmetricKeyRotator:
    """대칭 키 로테이터 테스트"""

    @pytest.mark.asyncio
    async def test_rotator_initialization(self):
        """로테이터 초기화 테스트"""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "rotator_key.json")
            
            rotator = SymmetricKeyRotator(
                usage_type=UsageType.AES256,
                rotation_interval_days=30,
                load_type=LoadType.FILE,
                options=FileLoadOptions(file_path=file_path)
            )
            
            await rotator.init()
            
            assert rotator.current_key is not None
            assert rotator.current_key.usage_type == UsageType.AES256
            assert os.path.exists(file_path)
            
            rotator.stop_scheduler()

    @pytest.mark.asyncio
    async def test_rotator_loads_existing_key(self):
        """로테이터가 기존 키를 로드하는지 테스트"""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "existing_key.json")
            options = FileLoadOptions(file_path=file_path)
            
            # 기존 키 생성 및 저장
            existing_key = generate_symmetric_key(UsageType.AES256, rotation_interval_days=30)
            await save_symmetric_key(existing_key, LoadType.FILE, options=options)
            
            # 로테이터 초기화
            rotator = SymmetricKeyRotator(
                usage_type=UsageType.AES256,
                rotation_interval_days=30,
                load_type=LoadType.FILE,
                options=options
            )
            
            await rotator.init()
            
            # 기존 키가 로드되었는지 확인
            assert rotator.current_key.kid == existing_key.kid
            assert rotator.current_key.key == existing_key.key
            
            rotator.stop_scheduler()

    @pytest.mark.asyncio
    async def test_manual_key_rotation(self):
        """수동 키 회전 테스트"""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "rotation_test.json")
            
            rotator = SymmetricKeyRotator(
                usage_type=UsageType.AES256,
                rotation_interval_days=1,
                load_type=LoadType.FILE,
                options=FileLoadOptions(file_path=file_path)
            )
            
            await rotator.init()
            old_kid = rotator.current_key.kid
            old_key = rotator.current_key.key
            
            # 키 회전 실행
            await rotator.rotate_key()
            
            # 새 키가 생성되었는지 확인
            assert rotator.current_key.kid != old_kid
            assert rotator.current_key.key != old_key
            assert os.path.exists(file_path)
            
            # 파일에 저장되었는지 확인
            loaded_key = await load_symmetric_key(
                UsageType.AES256,
                LoadType.FILE,
                rotation_interval_days=1,
                options=FileLoadOptions(file_path=file_path)
            )
            assert loaded_key.kid == rotator.current_key.kid
            
            rotator.stop_scheduler()

    @pytest.mark.asyncio
    async def test_rotator_invalid_options(self):
        """로테이터 잘못된 옵션 테스트"""
        with pytest.raises(TypeError, match="must be a FileLoadOptions instance"):
            rotator = SymmetricKeyRotator(
                usage_type=UsageType.AES256,
                rotation_interval_days=30,
                load_type=LoadType.FILE,
                options=None
            )

    @pytest.mark.asyncio
    async def test_rotator_missing_file_path(self):
        """로테이터 파일 경로 누락 테스트"""
        with pytest.raises(ValueError, match="file_path is required"):
            rotator = SymmetricKeyRotator(
                usage_type=UsageType.AES256,
                rotation_interval_days=30,
                load_type=LoadType.FILE,
                options=FileLoadOptions(file_path="")
            )

    @pytest.mark.asyncio
    async def test_scheduler_starts(self):
        """스케줄러가 시작되는지 테스트"""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "scheduler_test.json")
            
            rotator = SymmetricKeyRotator(
                usage_type=UsageType.AES256,
                rotation_interval_days=30,
                load_type=LoadType.FILE,
                options=FileLoadOptions(file_path=file_path)
            )
            
            await rotator.init()
            
            # 스케줄러가 실행 중인지 확인
            assert rotator.scheduler.running
            
            rotator.stop_scheduler()
            # Note: AsyncIOScheduler.shutdown() is asynchronous, so we just verify stop_scheduler was called

    @pytest.mark.asyncio
    async def test_rotator_with_different_usage_types(self):
        """다양한 UsageType으로 로테이터 테스트"""
        usage_types = [
            UsageType.AES128,
            UsageType.AES256,
            UsageType.SHA256_HMAC,
            UsageType.SHA512_HMAC
        ]
        
        with tempfile.TemporaryDirectory() as tmpdir:
            for usage_type in usage_types:
                file_path = os.path.join(tmpdir, f"{usage_type.name}.json")
                
                rotator = SymmetricKeyRotator(
                    usage_type=usage_type,
                    rotation_interval_days=30,
                    load_type=LoadType.FILE,
                    options=FileLoadOptions(file_path=file_path)
                )
                
                await rotator.init()
                
                assert rotator.current_key.usage_type == usage_type
                assert len(rotator.current_key.key) == usage_type.value.key_length_bytes
                
                rotator.stop_scheduler()
