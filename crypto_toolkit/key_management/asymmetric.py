# coding: utf-8
# crypto_toolkit/key_management/asymmetric.py

# Standard Library
import os
from enum import Enum


class LoadType(Enum):
    """
    최초 키 로드, 생성/업데이트 할 장소

    AWS KMS 같은거는 여기다가 타입 추가해두고 로직 구현 하면 됨
    """
    FILE = 'FILE'


class RSAKeySize(Enum):
    """
    RSA 키 크기 옵션
    """
    RSA2048 = 2048
    RSA4096 = 4096


def generate_asymmetric_key():
    """
    비대칭 키를 생성하는 함수
    """
    pass


def load_asymmetric_key():
    """
    비대칭 키를 로드하는 함수
    """
    pass

def save_asymmetric_key():
    """
    비대칭 키를 저장하는 함수
    """
    pass

class AsymmetricKeyRotator:
    """
    비대칭 키를 회전하는 클래스
    """
    pass