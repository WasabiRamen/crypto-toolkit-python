import string
import random
from datetime import datetime

def generate_kid(prefix: str, created_at: datetime) -> str:
    """
    KEY ID 생성 공동유틸

    키 형식: prefix-yyyy-mm-dd_(8자리 랜덤 문자열)

    Description:
        비동기 처리할 만큼 무거운 작업이 아니므로 동기 함수로 구현
        8자리 랜덤 문자열은 소문자+숫자 조합
    """
    created_date = created_at.strftime("%Y-%m-%d")
    chars = string.ascii_lowercase + string.digits
    key_random  = ''.join(random.choices(chars, k=8))
    return f"{prefix}-{created_date}-{key_random}"