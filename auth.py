import requests
from flask import session, redirect, url_for, request
from database import get_user_by_kakao_id, create_user
from config import KAKAO_REST_API_KEY, KAKAO_CLIENT_SECRET, KAKAO_REDIRECT_URI

def is_logged_in():
    """사용자 로그인 상태 확인"""
    return 'user_id' in session

def get_kakao_login_url():
    """카카오 로그인 URL 생성"""
    return f"https://kauth.kakao.com/oauth/authorize?client_id={KAKAO_REST_API_KEY}&redirect_uri={KAKAO_REDIRECT_URI}&response_type=code"

def process_kakao_callback(code):
    """카카오 로그인 콜백 처리"""
    try:
        # 액세스 토큰 요청
        token_url = "https://kauth.kakao.com/oauth/token"
        token_data = {
            "grant_type": "authorization_code",
            "client_id": KAKAO_REST_API_KEY,
            "client_secret": KAKAO_CLIENT_SECRET,
            "redirect_uri": KAKAO_REDIRECT_URI,
            "code": code
        }
        
        token_response = requests.post(token_url, data=token_data)
        token_response.raise_for_status()
        token_json = token_response.json()
        access_token = token_json.get("access_token")
        
        if not access_token:
            return {"error": "액세스 토큰을 가져오지 못했습니다."}
        
        # 사용자 정보 요청
        user_url = "https://kapi.kakao.com/v2/user/me"
        headers = {
            "Authorization": f"Bearer {access_token}"
        }
        
        user_response = requests.get(user_url, headers=headers)
        user_response.raise_for_status()
        user_json = user_response.json()
        
        kakao_id = str(user_json.get("id"))
        if not kakao_id:
            return {"error": "카카오 ID를 가져오지 못했습니다."}
        
        # 프로필 정보 추출
        properties = user_json.get("properties", {})
        nickname = properties.get("nickname")
        profile_image = properties.get("profile_image")
        
        # 사용자 조회 또는 생성
        user = get_user_by_kakao_id(kakao_id)
        if not user:
            user = create_user(kakao_id, nickname, profile_image)
        
        # 세션에 사용자 정보 저장
        session['user_id'] = user.id
        session['nickname'] = nickname
        session['profile_image'] = profile_image
        
        return {"success": True, "user": user}
        
    except requests.exceptions.RequestException as e:
        return {"error": f"API 호출 중 오류 발생: {str(e)}"}
    except Exception as e:
        return {"error": f"예상치 못한 오류 발생: {str(e)}"}

def logout():
    """로그아웃 처리"""
    session.pop('user_id', None)
    session.pop('nickname', None)
    session.pop('profile_image', None) 