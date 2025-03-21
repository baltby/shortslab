import os
from dotenv import load_dotenv
from cryptography.fernet import Fernet
import base64

# .env 파일 로드 시도
try:
    load_dotenv()
    print("환경 변수 로드 성공")
except Exception as e:
    print(f"환경 변수 로드 실패: {str(e)}")

# Flask 설정
SECRET_KEY = os.getenv('SECRET_KEY', 'default_secret_key_for_flask_app_security')
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///users.db')

# Apify 설정
APIFY_TOKEN = os.getenv('APIFY_TOKEN', '')
APIFY_BASE_URL = os.getenv('APIFY_BASE_URL', 'https://api.apify.com/v2')
APIFY_ACTOR_ID = os.getenv('APIFY_ACTOR_ID', 'streamers/youtube-scraper')

# 카카오 설정
KAKAO_REST_API_KEY = os.getenv('KAKAO_REST_API_KEY', '')
KAKAO_CLIENT_SECRET = os.getenv('KAKAO_CLIENT_SECRET', '')
KAKAO_JAVASCRIPT_KEY = os.getenv('KAKAO_JAVASCRIPT_KEY', '')
KAKAO_REDIRECT_URI = os.getenv('KAKAO_REDIRECT_URI', 'http://localhost:7777/login/kakao/callback')

# 사용 제한 설정
MAX_USAGE_PER_DAY = int(os.getenv('MAX_USAGE_PER_DAY', 10))
MAX_USAGE_NON_LOGIN = 1
MAX_SYSTEM_USAGE_PER_DAY = int(os.getenv('MAX_SYSTEM_USAGE_PER_DAY', 500))

# 암호화 설정
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY')
if not ENCRYPTION_KEY:
    # 환경 변수에 키가 없으면 새로 생성
    try:
        ENCRYPTION_KEY = Fernet.generate_key().decode('utf-8')
        print(f"새 암호화 키 생성: {ENCRYPTION_KEY[:10]}...")
        # .env 파일에 키 추가 시도 (개발 환경용)
        try:
            with open('.env', 'a') as f:
                f.write(f"\nENCRYPTION_KEY={ENCRYPTION_KEY}")
            print(".env 파일에 암호화 키 저장 성공")
        except Exception as e:
            print(f".env 파일에 암호화 키 저장 실패: {str(e)}")
    except Exception as e:
        print(f"암호화 키 생성 실패: {str(e)}")
        # 기본 키 설정
        ENCRYPTION_KEY = 'RmVybmV0IGtleSBnZW5lcmF0ZWQgZm9yIHNob3J0c2xhYg=='
        print("기본 암호화 키 사용")
else:
    # 키가 올바른 형식인지 확인
    try:
        Fernet(ENCRYPTION_KEY.encode())
        print("기존 암호화 키 사용")
    except Exception as e:
        # 올바르지 않은 형식이면 새 키 생성
        try:
            ENCRYPTION_KEY = Fernet.generate_key().decode()
            print(f"경고: ENCRYPTION_KEY가 올바른 형식이 아닙니다. 새 키 생성: {ENCRYPTION_KEY[:10]}...")
        except:
            # 기본 키 설정
            ENCRYPTION_KEY = 'RmVybmV0IGtleSBnZW5lcmF0ZWQgZm9yIHNob3J0c2xhYg=='
            print("기본 암호화 키 사용")