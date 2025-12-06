# coding: utf-8
# tests/test_key_management_asymmetric.py

import pytest
import asyncio
import json
import os
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from crypto_toolkit.key_management.asymmetric import (
    AsymmetricKeyPair,
    AsymmetricKeyRotator,
    RSAKeySize,
    LoadType,
    FileLoadOptions,
    generate_asymmetric_key,
    load_asymmetric_key,
    save_asymmetric_key,
)


class TestAsymmetricKeyGeneration:
    """비대칭 키 쌍 생성 테스트"""

    def test_generate_rsa2048_key(self):
        """RSA2048 키 쌍 생성 테스트"""
        key_pair = generate_asymmetric_key(RSAKeySize.RSA2048, rotation_interval_days=90)
        
        assert key_pair.kid is not None
        assert len(key_pair.kid) > 0
        assert key_pair.private_key is not None
        assert key_pair.public_key is not None
        assert key_pair.key_size == RSAKeySize.RSA2048
        assert key_pair.created_at is not None
        assert key_pair.expires_at is not None
        assert key_pair.expires_at > key_pair.created_at
        assert (key_pair.expires_at - key_pair.created_at).days == 90
        
        # PEM 형식 확인
        assert b'BEGIN PRIVATE KEY' in key_pair.private_key
        assert b'END PRIVATE KEY' in key_pair.private_key
        assert b'BEGIN PUBLIC KEY' in key_pair.public_key
        assert b'END PUBLIC KEY' in key_pair.public_key

    def test_generate_rsa4096_key(self):
        """RSA4096 키 쌍 생성 테스트"""
        key_pair = generate_asymmetric_key(RSAKeySize.RSA4096, rotation_interval_days=180)
        
        assert key_pair.key_size == RSAKeySize.RSA4096
        assert (key_pair.expires_at - key_pair.created_at).days == 180

    def test_key_pairs_are_unique(self):
        """생성된 키 쌍이 고유한지 테스트"""
        key_pair1 = generate_asymmetric_key(RSAKeySize.RSA2048, rotation_interval_days=90)
        key_pair2 = generate_asymmetric_key(RSAKeySize.RSA2048, rotation_interval_days=90)
        
        assert key_pair1.kid != key_pair2.kid
        assert key_pair1.private_key != key_pair2.private_key
        assert key_pair1.public_key != key_pair2.public_key

    def test_private_and_public_key_match(self):
        """개인키와 공개키가 매칭되는지 테스트"""
        key_pair = generate_asymmetric_key(RSAKeySize.RSA2048, rotation_interval_days=90)
        
        # 개인키에서 공개키 추출
        private_key_obj = serialization.load_pem_private_key(
            key_pair.private_key,
            password=None,
            backend=default_backend()
        )
        derived_public_key = private_key_obj.public_key()
        derived_public_pem = derived_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # 생성된 공개키와 비교
        assert derived_public_pem == key_pair.public_key

    def test_key_pair_getitem_access(self):
        """AsymmetricKeyPair의 __getitem__ 접근 테스트"""
        key_pair = generate_asymmetric_key(RSAKeySize.RSA2048, rotation_interval_days=90)
        
        assert key_pair['kid'] == key_pair.kid
        assert key_pair['private_key'] == key_pair.private_key
        assert key_pair['public_key'] == key_pair.public_key
        assert key_pair['key_size'] == key_pair.key_size
        assert key_pair['created_at'] == key_pair.created_at
        assert key_pair['expires_at'] == key_pair.expires_at


class TestAsymmetricKeySaveLoad:
    """비대칭 키 쌍 저장 및 로드 테스트"""

    @pytest.mark.asyncio
    async def test_save_and_load_key_pair(self):
        """키 쌍 저장 후 로드 테스트"""
        with tempfile.TemporaryDirectory() as tmpdir:
            private_path = os.path.join(tmpdir, "private_key.json")
            public_path = os.path.join(tmpdir, "public_key.json")
            options = FileLoadOptions(
                private_key_path=private_path,
                public_key_path=public_path
            )
            
            # 키 쌍 생성 및 저장
            original_key_pair = generate_asymmetric_key(RSAKeySize.RSA2048, rotation_interval_days=90)
            await save_asymmetric_key(original_key_pair, LoadType.FILE, options=options)
            
            # 파일 존재 확인
            assert os.path.exists(private_path)
            assert os.path.exists(public_path)
            
            # 키 쌍 로드
            loaded_key_pair = await load_asymmetric_key(
                RSAKeySize.RSA2048,
                LoadType.FILE,
                rotation_interval_days=90,
                options=options
            )
            
            # 검증
            assert loaded_key_pair.kid == original_key_pair.kid
            assert loaded_key_pair.private_key == original_key_pair.private_key
            assert loaded_key_pair.public_key == original_key_pair.public_key
            assert loaded_key_pair.key_size == original_key_pair.key_size
            assert loaded_key_pair.created_at == original_key_pair.created_at
            assert loaded_key_pair.expires_at == original_key_pair.expires_at

    @pytest.mark.asyncio
    async def test_load_creates_new_key_pair_if_not_exists(self):
        """파일이 없으면 새 키 쌍 생성 테스트"""
        with tempfile.TemporaryDirectory() as tmpdir:
            private_path = os.path.join(tmpdir, "new_private.json")
            public_path = os.path.join(tmpdir, "new_public.json")
            options = FileLoadOptions(
                private_key_path=private_path,
                public_key_path=public_path
            )
            
            # 파일이 없는 상태에서 로드
            key_pair = await load_asymmetric_key(
                RSAKeySize.RSA2048,
                LoadType.FILE,
                rotation_interval_days=90,
                options=options
            )
            
            # 새 키 쌍이 생성되었는지 확인
            assert key_pair.kid is not None
            assert key_pair.private_key is not None
            assert key_pair.public_key is not None
            assert os.path.exists(private_path)
            assert os.path.exists(public_path)

    @pytest.mark.asyncio
    async def test_load_creates_directory_if_not_exists(self):
        """디렉토리가 없으면 생성 테스트"""
        with tempfile.TemporaryDirectory() as tmpdir:
            private_path = os.path.join(tmpdir, "subdir", "private_key.json")
            public_path = os.path.join(tmpdir, "subdir", "public_key.json")
            options = FileLoadOptions(
                private_key_path=private_path,
                public_key_path=public_path
            )
            
            # 디렉토리가 없는 상태에서 로드
            key_pair = await load_asymmetric_key(
                RSAKeySize.RSA2048,
                LoadType.FILE,
                rotation_interval_days=90,
                options=options
            )
            
            assert os.path.exists(private_path)
            assert os.path.exists(public_path)
            assert os.path.exists(os.path.dirname(private_path))

    @pytest.mark.asyncio
    async def test_save_key_pair_validation(self):
        """키 쌍 저장 시 검증 테스트"""
        with tempfile.TemporaryDirectory() as tmpdir:
            private_path = os.path.join(tmpdir, "private_key.json")
            public_path = os.path.join(tmpdir, "public_key.json")
            options = FileLoadOptions(
                private_key_path=private_path,
                public_key_path=public_path
            )
            key_pair = generate_asymmetric_key(RSAKeySize.RSA2048, rotation_interval_days=90)
            
            await save_asymmetric_key(key_pair, LoadType.FILE, options=options)
            
            # Private Key JSON 검증
            with open(private_path, 'r') as f:
                private_data = json.load(f)
            
            assert 'kid' in private_data
            assert 'private_key' in private_data
            assert 'key_size' in private_data
            assert 'created_at' in private_data
            assert 'expires_at' in private_data
            assert private_data['key_size'] == 'RSA2048'
            
            # Public Key JSON 검증
            with open(public_path, 'r') as f:
                public_data = json.load(f)
            
            assert 'kid' in public_data
            assert 'public_key' in public_data
            assert 'key_size' in public_data
            assert public_data['kid'] == private_data['kid']

    @pytest.mark.asyncio
    async def test_load_with_invalid_private_key_json(self):
        """잘못된 Private Key JSON 로드 시 에러 테스트"""
        with tempfile.TemporaryDirectory() as tmpdir:
            private_path = os.path.join(tmpdir, "invalid_private.json")
            public_path = os.path.join(tmpdir, "public_key.json")
            options = FileLoadOptions(
                private_key_path=private_path,
                public_key_path=public_path
            )
            
            # 잘못된 JSON 작성 (둘 다 작성해야 파일이 존재하는 것으로 인식)
            with open(private_path, 'w') as f:
                f.write("{ invalid json }")
            with open(public_path, 'w') as f:
                f.write("{ invalid json }")
            
            with pytest.raises(ValueError, match="Invalid JSON format in private key file"):
                await load_asymmetric_key(
                    RSAKeySize.RSA2048,
                    LoadType.FILE,
                    rotation_interval_days=90,
                    options=options
                )

    @pytest.mark.asyncio
    async def test_load_with_invalid_public_key_json(self):
        """잘못된 Public Key JSON 로드 시 에러 테스트"""
        with tempfile.TemporaryDirectory() as tmpdir:
            private_path = os.path.join(tmpdir, "private_key.json")
            public_path = os.path.join(tmpdir, "invalid_public.json")
            options = FileLoadOptions(
                private_key_path=private_path,
                public_key_path=public_path
            )
            
            # 올바른 Private Key 저장
            key_pair = generate_asymmetric_key(RSAKeySize.RSA2048, rotation_interval_days=90)
            private_data = {
                'kid': key_pair.kid,
                'private_key': key_pair.private_key.decode('utf-8'),
                'key_size': key_pair.key_size.name,
                'created_at': key_pair.created_at.isoformat(),
                'expires_at': key_pair.expires_at.isoformat()
            }
            with open(private_path, 'w') as f:
                json.dump(private_data, f)
            
            # 잘못된 Public Key JSON 작성
            with open(public_path, 'w') as f:
                f.write("{ invalid json }")
            
            with pytest.raises(ValueError, match="Invalid JSON format in public key file"):
                await load_asymmetric_key(
                    RSAKeySize.RSA2048,
                    LoadType.FILE,
                    rotation_interval_days=90,
                    options=options
                )

    @pytest.mark.asyncio
    async def test_load_with_missing_private_key_fields(self):
        """Private Key 필수 필드가 없으면 에러 테스트"""
        with tempfile.TemporaryDirectory() as tmpdir:
            private_path = os.path.join(tmpdir, "incomplete_private.json")
            public_path = os.path.join(tmpdir, "public_key.json")
            options = FileLoadOptions(
                private_key_path=private_path,
                public_key_path=public_path
            )
            
            # 불완전한 Private Key 작성
            with open(private_path, 'w') as f:
                json.dump({"kid": "test"}, f)
            
            # Public Key 작성
            with open(public_path, 'w') as f:
                json.dump({"kid": "test", "public_key": "test"}, f)
            
            with pytest.raises(ValueError, match="Invalid private key data"):
                await load_asymmetric_key(
                    RSAKeySize.RSA2048,
                    LoadType.FILE,
                    rotation_interval_days=90,
                    options=options
                )

    @pytest.mark.asyncio
    async def test_load_with_missing_public_key_fields(self):
        """Public Key 필수 필드가 없으면 에러 테스트"""
        with tempfile.TemporaryDirectory() as tmpdir:
            private_path = os.path.join(tmpdir, "private_key.json")
            public_path = os.path.join(tmpdir, "incomplete_public.json")
            options = FileLoadOptions(
                private_key_path=private_path,
                public_key_path=public_path
            )
            
            # 올바른 Private Key 저장
            key_pair = generate_asymmetric_key(RSAKeySize.RSA2048, rotation_interval_days=90)
            private_data = {
                'kid': key_pair.kid,
                'private_key': key_pair.private_key.decode('utf-8'),
                'key_size': key_pair.key_size.name,
                'created_at': key_pair.created_at.isoformat(),
                'expires_at': key_pair.expires_at.isoformat()
            }
            with open(private_path, 'w') as f:
                json.dump(private_data, f)
            
            # 불완전한 Public Key 작성
            with open(public_path, 'w') as f:
                json.dump({"kid": "test"}, f)
            
            with pytest.raises(ValueError, match="Invalid public key data"):
                await load_asymmetric_key(
                    RSAKeySize.RSA2048,
                    LoadType.FILE,
                    rotation_interval_days=90,
                    options=options
                )

    @pytest.mark.asyncio
    async def test_load_with_kid_mismatch(self):
        """Private와 Public Key의 kid가 일치하지 않으면 에러 테스트"""
        with tempfile.TemporaryDirectory() as tmpdir:
            private_path = os.path.join(tmpdir, "private_key.json")
            public_path = os.path.join(tmpdir, "public_key.json")
            options = FileLoadOptions(
                private_key_path=private_path,
                public_key_path=public_path
            )
            
            # 다른 kid로 키 쌍 저장
            key_pair = generate_asymmetric_key(RSAKeySize.RSA2048, rotation_interval_days=90)
            
            private_data = {
                'kid': 'private_kid',
                'private_key': key_pair.private_key.decode('utf-8'),
                'key_size': key_pair.key_size.name,
                'created_at': key_pair.created_at.isoformat(),
                'expires_at': key_pair.expires_at.isoformat()
            }
            
            public_data = {
                'kid': 'public_kid',
                'public_key': key_pair.public_key.decode('utf-8'),
                'key_size': key_pair.key_size.name,
                'created_at': key_pair.created_at.isoformat(),
                'expires_at': key_pair.expires_at.isoformat()
            }
            
            with open(private_path, 'w') as f:
                json.dump(private_data, f)
            with open(public_path, 'w') as f:
                json.dump(public_data, f)
            
            with pytest.raises(ValueError, match="kid mismatch"):
                await load_asymmetric_key(
                    RSAKeySize.RSA2048,
                    LoadType.FILE,
                    rotation_interval_days=90,
                    options=options
                )

    @pytest.mark.asyncio
    async def test_save_invalid_file_paths(self):
        """잘못된 파일 경로로 저장 시 에러 테스트"""
        options = FileLoadOptions(
            private_key_path="invalid.txt",
            public_key_path="invalid.txt"
        )
        key_pair = generate_asymmetric_key(RSAKeySize.RSA2048, rotation_interval_days=90)
        
        with pytest.raises(ValueError, match="must point to .json files"):
            await save_asymmetric_key(key_pair, LoadType.FILE, options=options)

    @pytest.mark.asyncio
    async def test_load_invalid_file_paths(self):
        """잘못된 파일 경로로 로드 시 에러 테스트"""
        options = FileLoadOptions(
            private_key_path="invalid.txt",
            public_key_path="invalid.txt"
        )
        
        with pytest.raises(ValueError, match="must point to .json files"):
            await load_asymmetric_key(
                RSAKeySize.RSA2048,
                LoadType.FILE,
                rotation_interval_days=90,
                options=options
            )

    @pytest.mark.asyncio
    async def test_invalid_load_type(self):
        """잘못된 LoadType 사용 시 에러 테스트"""
        with pytest.raises(ValueError, match="must be an instance of LoadType"):
            await load_asymmetric_key(
                RSAKeySize.RSA2048,
                "INVALID",  # type: ignore
                rotation_interval_days=90,
                options=None
            )

    @pytest.mark.asyncio
    async def test_missing_options_for_file_load_type(self):
        """FILE LoadType인데 options 없으면 에러 테스트"""
        with pytest.raises(TypeError, match="must be a FileLoadOptions instance"):
            await load_asymmetric_key(
                RSAKeySize.RSA2048,
                LoadType.FILE,
                rotation_interval_days=90,
                options=None
            )

    @pytest.mark.asyncio
    async def test_timezone_handling(self):
        """타임존 처리 테스트"""
        with tempfile.TemporaryDirectory() as tmpdir:
            private_path = os.path.join(tmpdir, "private_key.json")
            public_path = os.path.join(tmpdir, "public_key.json")
            options = FileLoadOptions(
                private_key_path=private_path,
                public_key_path=public_path
            )
            
            # 키 쌍 생성 및 저장
            original_key_pair = generate_asymmetric_key(RSAKeySize.RSA2048, rotation_interval_days=90)
            await save_asymmetric_key(original_key_pair, LoadType.FILE, options=options)
            
            # 키 쌍 로드
            loaded_key_pair = await load_asymmetric_key(
                RSAKeySize.RSA2048,
                LoadType.FILE,
                rotation_interval_days=90,
                options=options
            )
            
            # 타임존 확인
            assert loaded_key_pair.created_at.tzinfo is not None
            assert loaded_key_pair.expires_at.tzinfo is not None
            assert loaded_key_pair.created_at.tzinfo == timezone.utc
            assert loaded_key_pair.expires_at.tzinfo == timezone.utc


class TestAsymmetricKeyRotator:
    """비대칭 키 로테이터 테스트"""

    @pytest.mark.asyncio
    async def test_rotator_initialization(self):
        """로테이터 초기화 테스트"""
        with tempfile.TemporaryDirectory() as tmpdir:
            private_path = os.path.join(tmpdir, "rotator_private.json")
            public_path = os.path.join(tmpdir, "rotator_public.json")
            
            rotator = AsymmetricKeyRotator(
                key_size=RSAKeySize.RSA2048,
                rotation_interval_days=90,
                load_type=LoadType.FILE,
                options=FileLoadOptions(
                    private_key_path=private_path,
                    public_key_path=public_path
                )
            )
            
            await rotator.init()
            
            assert rotator.current_key_pair is not None
            assert rotator.current_key_pair.key_size == RSAKeySize.RSA2048
            assert os.path.exists(private_path)
            assert os.path.exists(public_path)
            
            rotator.stop_scheduler()

    @pytest.mark.asyncio
    async def test_rotator_loads_existing_key_pair(self):
        """로테이터가 기존 키 쌍을 로드하는지 테스트"""
        with tempfile.TemporaryDirectory() as tmpdir:
            private_path = os.path.join(tmpdir, "existing_private.json")
            public_path = os.path.join(tmpdir, "existing_public.json")
            options = FileLoadOptions(
                private_key_path=private_path,
                public_key_path=public_path
            )
            
            # 기존 키 쌍 생성 및 저장
            existing_key_pair = generate_asymmetric_key(RSAKeySize.RSA2048, rotation_interval_days=90)
            await save_asymmetric_key(existing_key_pair, LoadType.FILE, options=options)
            
            # 로테이터 초기화
            rotator = AsymmetricKeyRotator(
                key_size=RSAKeySize.RSA2048,
                rotation_interval_days=90,
                load_type=LoadType.FILE,
                options=options
            )
            
            await rotator.init()
            
            # 기존 키 쌍이 로드되었는지 확인
            assert rotator.current_key_pair.kid == existing_key_pair.kid
            assert rotator.current_key_pair.private_key == existing_key_pair.private_key
            assert rotator.current_key_pair.public_key == existing_key_pair.public_key
            
            rotator.stop_scheduler()

    @pytest.mark.asyncio
    async def test_manual_key_rotation(self):
        """수동 키 회전 테스트"""
        with tempfile.TemporaryDirectory() as tmpdir:
            private_path = os.path.join(tmpdir, "rotation_private.json")
            public_path = os.path.join(tmpdir, "rotation_public.json")
            
            rotator = AsymmetricKeyRotator(
                key_size=RSAKeySize.RSA2048,
                rotation_interval_days=1,
                load_type=LoadType.FILE,
                options=FileLoadOptions(
                    private_key_path=private_path,
                    public_key_path=public_path
                )
            )
            
            await rotator.init()
            old_kid = rotator.current_key_pair.kid
            old_private_key = rotator.current_key_pair.private_key
            old_public_key = rotator.current_key_pair.public_key
            
            # 키 회전 실행
            await rotator.rotate_key()
            
            # 새 키 쌍이 생성되었는지 확인
            assert rotator.current_key_pair.kid != old_kid
            assert rotator.current_key_pair.private_key != old_private_key
            assert rotator.current_key_pair.public_key != old_public_key
            assert os.path.exists(private_path)
            assert os.path.exists(public_path)
            
            # 파일에 저장되었는지 확인
            loaded_key_pair = await load_asymmetric_key(
                RSAKeySize.RSA2048,
                LoadType.FILE,
                rotation_interval_days=1,
                options=FileLoadOptions(
                    private_key_path=private_path,
                    public_key_path=public_path
                )
            )
            assert loaded_key_pair.kid == rotator.current_key_pair.kid
            
            rotator.stop_scheduler()

    @pytest.mark.asyncio
    async def test_rotator_invalid_options(self):
        """로테이터 잘못된 옵션 테스트"""
        with pytest.raises(TypeError, match="must be a FileLoadOptions instance"):
            rotator = AsymmetricKeyRotator(
                key_size=RSAKeySize.RSA2048,
                rotation_interval_days=90,
                load_type=LoadType.FILE,
                options=None
            )

    @pytest.mark.asyncio
    async def test_rotator_missing_file_paths(self):
        """로테이터 파일 경로 누락 테스트"""
        with pytest.raises(ValueError, match="private_key_path and public_key_path are required"):
            rotator = AsymmetricKeyRotator(
                key_size=RSAKeySize.RSA2048,
                rotation_interval_days=90,
                load_type=LoadType.FILE,
                options=FileLoadOptions(
                    private_key_path="",
                    public_key_path=""
                )
            )

    @pytest.mark.asyncio
    async def test_scheduler_starts(self):
        """스케줄러가 시작되는지 테스트"""
        with tempfile.TemporaryDirectory() as tmpdir:
            private_path = os.path.join(tmpdir, "scheduler_private.json")
            public_path = os.path.join(tmpdir, "scheduler_public.json")
            
            rotator = AsymmetricKeyRotator(
                key_size=RSAKeySize.RSA2048,
                rotation_interval_days=90,
                load_type=LoadType.FILE,
                options=FileLoadOptions(
                    private_key_path=private_path,
                    public_key_path=public_path
                )
            )
            
            await rotator.init()
            
            # 스케줄러가 실행 중인지 확인
            assert rotator.scheduler.running
            
            rotator.stop_scheduler()
            # Note: AsyncIOScheduler.shutdown() is asynchronous, so we just verify stop_scheduler was called

    @pytest.mark.asyncio
    async def test_rotator_with_different_key_sizes(self):
        """다양한 RSAKeySize로 로테이터 테스트"""
        key_sizes = [RSAKeySize.RSA2048, RSAKeySize.RSA4096]
        
        with tempfile.TemporaryDirectory() as tmpdir:
            for key_size in key_sizes:
                private_path = os.path.join(tmpdir, f"{key_size.name}_private.json")
                public_path = os.path.join(tmpdir, f"{key_size.name}_public.json")
                
                rotator = AsymmetricKeyRotator(
                    key_size=key_size,
                    rotation_interval_days=90,
                    load_type=LoadType.FILE,
                    options=FileLoadOptions(
                        private_key_path=private_path,
                        public_key_path=public_path
                    )
                )
                
                await rotator.init()
                
                assert rotator.current_key_pair.key_size == key_size
                
                # 키 크기 확인
                private_key_obj = serialization.load_pem_private_key(
                    rotator.current_key_pair.private_key,
                    password=None,
                    backend=default_backend()
                )
                assert private_key_obj.key_size == key_size.value
                
                rotator.stop_scheduler()

    @pytest.mark.asyncio
    async def test_rotator_key_pair_validity(self):
        """로테이터가 생성한 키 쌍이 유효한지 테스트"""
        with tempfile.TemporaryDirectory() as tmpdir:
            private_path = os.path.join(tmpdir, "valid_private.json")
            public_path = os.path.join(tmpdir, "valid_public.json")
            
            rotator = AsymmetricKeyRotator(
                key_size=RSAKeySize.RSA2048,
                rotation_interval_days=90,
                load_type=LoadType.FILE,
                options=FileLoadOptions(
                    private_key_path=private_path,
                    public_key_path=public_path
                )
            )
            
            await rotator.init()
            
            # 개인키 로드 가능 확인
            private_key_obj = serialization.load_pem_private_key(
                rotator.current_key_pair.private_key,
                password=None,
                backend=default_backend()
            )
            assert private_key_obj is not None
            
            # 공개키 로드 가능 확인
            public_key_obj = serialization.load_pem_public_key(
                rotator.current_key_pair.public_key,
                backend=default_backend()
            )
            assert public_key_obj is not None
            
            # 개인키에서 파생된 공개키와 저장된 공개키 일치 확인
            derived_public_key = private_key_obj.public_key()
            derived_public_pem = derived_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            assert derived_public_pem == rotator.current_key_pair.public_key
            
            rotator.stop_scheduler()
