from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file
import io
from config import SECRET_KEY, DATABASE_URL, KAKAO_JAVASCRIPT_KEY, MAX_USAGE_PER_DAY
from youtube_scraper import get_youtube_data, extract_video_data
from database import db, User, check_non_login_usage, increment_non_login_usage
from auth import is_logged_in, get_kakao_login_url, process_kakao_callback, logout
import os

# Flask 앱 초기화
app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 데이터베이스 초기화
db.init_app(app)

# 앱 시작 시 데이터베이스 테이블 생성
with app.app_context():
    db.create_all()

@app.route('/', methods=['GET', 'POST'])
def index():
    """메인 페이지 및 URL 처리"""
    error = None
    video_data = None
    usage_info = get_usage_info()
    
    if request.method == 'POST':
        url = request.form.get('url')
        
        if not url:
            error = "URL을 입력해주세요."
        else:
            # 사용 제한 확인
            if is_logged_in():
                user = User.query.get(session['user_id'])
                if not user.check_usage_limit():
                    error = f"일일 사용 한도({MAX_USAGE_PER_DAY}회)를 초과했습니다."
                else:
                    # 데이터 가져오기
                    raw_data = get_youtube_data(url)
                    video_data = extract_video_data(raw_data)
                    
                    if "error" not in video_data:
                        # 사용 횟수 증가
                        user.increment_usage()
                        usage_info = get_usage_info()  # 업데이트된 사용 정보
            else:
                if not check_non_login_usage(session):
                    error = "비로그인 사용자는 1회만 사용 가능합니다. 로그인해주세요."
                else:
                    # 데이터 가져오기
                    raw_data = get_youtube_data(url)
                    video_data = extract_video_data(raw_data)
                    
                    if "error" not in video_data:
                        # 사용 횟수 증가
                        increment_non_login_usage(session)
                        usage_info = get_usage_info()  # 업데이트된 사용 정보
    
    return render_template('index.html', 
                          error=error, 
                          video_data=video_data, 
                          usage_info=usage_info,
                          is_logged_in=is_logged_in(),
                          kakao_javascript_key=KAKAO_JAVASCRIPT_KEY,
                          kakao_login_url=get_kakao_login_url())

@app.route('/download_subtitles/<video_id>')
def download_subtitles(video_id):
    """자막 다운로드"""
    # 세션에서 자막 데이터 가져오기 (또는 다시 API 호출)
    subtitles = session.get(f'subtitles_{video_id}')
    
    if not subtitles:
        return "자막을 찾을 수 없습니다.", 404
    
    # 텍스트 파일로 반환
    buffer = io.BytesIO()
    buffer.write(subtitles.encode('utf-8'))
    buffer.seek(0)
    
    return send_file(buffer, 
                    mimetype='text/plain', 
                    as_attachment=True, 
                    download_name=f'{video_id}_subtitles.txt')

@app.route('/login/kakao')
def kakao_login():
    """카카오 로그인 리다이렉트"""
    return redirect(get_kakao_login_url())

@app.route('/login/kakao/callback')
def kakao_callback():
    """카카오 로그인 콜백 처리"""
    code = request.args.get('code')
    
    if not code:
        return redirect(url_for('index', error="로그인 실패: 인증 코드가 없습니다."))
    
    result = process_kakao_callback(code)
    
    if "error" in result:
        return redirect(url_for('index', error=f"로그인 실패: {result['error']}"))
    
    return redirect(url_for('index'))

@app.route('/logout')
def logout_route():
    """로그아웃 처리"""
    logout()
    return redirect(url_for('index'))

def get_usage_info():
    """사용자의 사용 정보 가져오기"""
    if is_logged_in():
        user = User.query.get(session['user_id'])
        return {
            "type": "login",
            "count": user.usage_count,
            "max": MAX_USAGE_PER_DAY,
            "nickname": session.get('nickname', '사용자')
        }
    else:
        return {
            "type": "non_login",
            "count": session.get('non_login_usage', 0),
            "max": 1
        }

if __name__ == '__main__':
    # 환경 변수에서 포트 가져오기 (없으면 7777 사용)
    port = int(os.environ.get('PORT', 7777))
    app.run(host='0.0.0.0', port=port, debug=True) 