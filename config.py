import os
from dotenv import load_dotenv
from cryptography.fernet import Fernet
import base64

# .env 파일 로드
load_dotenv()

# Flask 설정
SECRET_KEY = os.getenv('SECRET_KEY')
DATABASE_URL = os.getenv('DATABASE_URL')

# Apify 설정
APIFY_TOKEN = os.getenv('APIFY_TOKEN')
APIFY_BASE_URL = os.getenv('APIFY_BASE_URL')
APIFY_ACTOR_ID = os.getenv('APIFY_ACTOR_ID')

# 카카오 설정
KAKAO_REST_API_KEY = os.getenv('KAKAO_REST_API_KEY')
KAKAO_CLIENT_SECRET = os.getenv('KAKAO_CLIENT_SECRET')
KAKAO_JAVASCRIPT_KEY = os.getenv('KAKAO_JAVASCRIPT_KEY')
KAKAO_REDIRECT_URI = os.getenv('KAKAO_REDIRECT_URI')

# 사용 제한 설정
MAX_USAGE_PER_DAY = int(os.getenv('MAX_USAGE_PER_DAY', 10))
MAX_USAGE_NON_LOGIN = 1
MAX_SYSTEM_USAGE_PER_DAY = int(os.getenv('MAX_SYSTEM_USAGE_PER_DAY', 500))

# 암호화 설정
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY')
if not ENCRYPTION_KEY:
    # 환경 변수에 키가 없으면 새로 생성
    ENCRYPTION_KEY = Fernet.generate_key().decode('utf-8')
    # .env 파일에 키 추가 (개발 환경용)
    try:
        with open('.env', 'a') as f:
            f.write(f"\nENCRYPTION_KEY={ENCRYPTION_KEY}")
    except:
        pass
else:
    # 키가 올바른 형식인지 확인
    try:
        Fernet(ENCRYPTION_KEY.encode())
    except Exception as e:
        # 올바르지 않은 형식이면 새 키 생성
        ENCRYPTION_KEY = Fernet.generate_key().decode()
        print(f"경고: ENCRYPTION_KEY가 올바른 형식이 아닙니다. 임시 키를 생성했습니다: {ENCRYPTION_KEY}") 