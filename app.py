from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file
import os
import json
import io
import tempfile
from datetime import datetime, timedelta, date
from youtube_scraper import get_youtube_data, extract_video_data
from database import get_db, User, UsageLog, db, get_user_by_kakao_id, create_user, get_user_logs, count_user_logs, delete_oldest_log, save_video_analysis, get_video_analysis, get_video_analysis_by_url, get_daily_usage, increment_daily_usage, reset_expired_usage, get_system_usage, increment_system_usage, check_system_usage_limit, is_admin_user, get_total_users_count
from config import KAKAO_REST_API_KEY, KAKAO_REDIRECT_URI, KAKAO_CLIENT_SECRET, MAX_SYSTEM_USAGE_PER_DAY
import requests
import time
import threading
from functools import wraps
from collections import deque
import random

# Flask 앱 생성
flask_app = Flask(__name__)
flask_app.secret_key = os.environ.get('SECRET_KEY', 'default_secret_key')

# 데이터베이스 설정
flask_app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
flask_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 데이터베이스 초기화
db.init_app(flask_app)

# 데이터베이스 테이블 생성
with flask_app.app_context():
    # 기존 테이블 구조 확인
    try:
        # created_at 컬럼이 없는지 확인
        db.engine.execute("SELECT created_at FROM user LIMIT 1")
        print("created_at 컬럼이 이미 존재합니다.")
    except:
        # created_at 컬럼 추가
        try:
            print("created_at 컬럼 추가 중...")
            db.engine.execute("ALTER TABLE user ADD COLUMN created_at DATETIME")
            db.engine.execute("UPDATE user SET created_at = CURRENT_TIMESTAMP")
            print("created_at 컬럼 추가 완료")
        except Exception as e:
            print(f"created_at 컬럼 추가 실패: {str(e)}")
    
    # 모든 테이블 생성
    db.create_all()
    print("모든 데이터베이스 테이블 생성 완료")
    
    # 만료된 사용량 기록 삭제
    reset_expired_usage()

# 요청 제한 설정
REQUEST_QUEUE = deque()
QUEUE_LOCK = threading.Lock()
MAX_QUEUE_SIZE = 10

# IP별 요청 제한 설정
IP_REQUEST_COUNTS = {}
IP_LOCK = threading.Lock()
MAX_REQUESTS_PER_HOUR = 60

# 동시 요청 제어를 위한 세마포어
request_semaphore = threading.Semaphore(1)
last_request_time = datetime.now() - timedelta(seconds=10)  # 초기값은 10초 전으로 설정

def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 클라이언트 IP 가져오기
        ip = request.remote_addr
        
        # 현재 시간
        now = datetime.now()
        
        # IP별 요청 카운트 확인
        with IP_LOCK:
            # 오래된 요청 정보 제거
            for ip_addr in list(IP_REQUEST_COUNTS.keys()):
                IP_REQUEST_COUNTS[ip_addr] = [t for t in IP_REQUEST_COUNTS[ip_addr] if now - t < timedelta(hours=1)]
            
            # 현재 IP의 요청 수 확인
            if ip not in IP_REQUEST_COUNTS:
                IP_REQUEST_COUNTS[ip] = []
            
            # 시간당 최대 요청 수 초과 확인
            if len(IP_REQUEST_COUNTS[ip]) >= MAX_REQUESTS_PER_HOUR:
                return jsonify({"error": "시간당 최대 요청 수를 초과했습니다. 잠시 후 다시 시도해주세요."}), 429
            
            # 요청 시간 기록
            IP_REQUEST_COUNTS[ip].append(now)
        
        # 대기열 확인
        with QUEUE_LOCK:
            # 대기열이 가득 찼는지 확인
            if len(REQUEST_QUEUE) >= MAX_QUEUE_SIZE:
                return jsonify({"error": "서버가 혼잡합니다. 잠시 후 다시 시도해주세요."}), 503
            
            # 요청을 대기열에 추가
            request_id = f"{ip}_{now.timestamp()}"
            REQUEST_QUEUE.append(request_id)
        
        try:
            # 함수 실행
            return f(*args, **kwargs)
        finally:
            # 대기열에서 요청 제거
            with QUEUE_LOCK:
                if request_id in REQUEST_QUEUE:
                    REQUEST_QUEUE.remove(request_id)
    
    return decorated_function

# 필터 등록
@flask_app.template_filter('format_number')
def format_number(value):
    """숫자를 천 단위로 구분하여 표시"""
    return f"{value:,}" if value else "0"

@flask_app.template_filter('format_date')
def format_date(value):
    """날짜 형식 변환"""
    if not value:
        return ""
    try:
        # ISO 형식 날짜를 YYYY-MM-DD 형식으로 변환
        return value.split('T')[0]
    except:
        return value

@flask_app.template_filter('nl2br')
def nl2br(value):
    """줄바꿈을 <br> 태그로 변환"""
    if not value:
        return ""
    return value.replace('\n', '<br>')

# 자막 다운로드 라우트 수정
@flask_app.route('/download_subtitles', methods=['POST'])
@rate_limit
def download_subtitles():
    try:
        data = request.get_json()
        subtitles = data.get('subtitles', '')
        title = data.get('title', 'subtitles')
        
        # 파일명에 사용할 수 없는 문자 제거
        safe_title = "".join([c for c in title if c.isalpha() or c.isdigit() or c==' ']).rstrip()
        if not safe_title:
            safe_title = 'subtitles'
        
        # 메모리에서 파일 생성
        subtitles_bytes = subtitles.encode('utf-8')
        subtitles_io = io.BytesIO(subtitles_bytes)
        subtitles_io.seek(0)
        
        # 파일 전송
        return send_file(
            subtitles_io,
            mimetype='text/plain',
            as_attachment=True,
            download_name=f"{safe_title}.txt"
        )
        
    except Exception as e:
        print(f"다운로드 오류: {str(e)}")
        return jsonify({"error": f"다운로드 중 오류가 발생했습니다: {str(e)}"}), 500

# 메인 페이지 라우트
@flask_app.route('/')
def index():
    # 클라이언트 IP 가져오기
    ip_address = request.remote_addr
    
    # 로그인 상태 확인
    is_logged_in = 'user_id' in session
    is_admin = False
    
    # 사용자 정보 및 관리자 확인
    if is_logged_in:
        user_id = session['user_id']
        user = User.query.get(user_id)
        if user:
            is_admin = is_admin_user(user.decrypted_kakao_id)
    
    # 관리자용 시스템 정보
    admin_info = None
    if is_admin:
        system_usage = get_system_usage()
        total_users = get_total_users_count()
        admin_info = {
            'system_usage': system_usage,
            'max_usage': MAX_SYSTEM_USAGE_PER_DAY,
            'total_users': total_users,
            'percent': min(100, int(system_usage / MAX_SYSTEM_USAGE_PER_DAY * 100))
        }
    
    # 카카오 JavaScript 키 가져오기
    kakao_javascript_key = os.environ.get('KAKAO_JAVASCRIPT_KEY', '')
    
    return render_template('index.html', is_logged_in=is_logged_in, is_admin=is_admin, admin_info=admin_info, kakao_javascript_key=kakao_javascript_key)

# 요청 전 미들웨어
@flask_app.before_request
def before_request():
    # 사용량 관련 라우트만 처리
    if request.endpoint == 'fetch_youtube_data':
        # 만료된 사용량 기록 삭제 (1일 1회)
        today = date.today().isoformat()
        if session.get('last_cleanup_date') != today:
            reset_expired_usage()
            session['last_cleanup_date'] = today

# YouTube 데이터 가져오기 라우트
@flask_app.route('/get_youtube_data', methods=['POST', 'GET'])
@rate_limit
def fetch_youtube_data():
    global last_request_time
    
    # 현재 시간 확인
    current_time = datetime.now()
    
    # 마지막 요청과의 시간 차이 계산
    time_since_last_request = (current_time - last_request_time).total_seconds()
    
    # 3초 이내에 다른 요청이 있었다면 딜레이 추가
    if time_since_last_request < 3:
        # 3초에서 경과 시간을 뺀 만큼 대기 (최소 0.5초, 최대 3초)
        delay_time = min(3, max(0.5, 3 - time_since_last_request))
        # 약간의 랜덤성 추가 (0.1~0.5초)
        delay_time += random.uniform(0.1, 0.5)
        # 백그라운드에서 대기
        time.sleep(delay_time)
    
    # 현재 요청 시간 업데이트
    last_request_time = datetime.now()
    
    # 클라이언트 IP 가져오기
    ip_address = request.remote_addr
    
    # 시스템 사용량 제한 확인
    if not check_system_usage_limit(MAX_SYSTEM_USAGE_PER_DAY):
        return render_template('index.html', error=f"죄송합니다. 오늘의 시스템 분석 한도가 초과되었습니다. 내일 다시 시도해주세요.", is_logged_in='user_id' in session)
    
    # 사용량 제한 확인
    is_logged_in = 'user_id' in session
    is_admin = False
    
    # 사용자 ID 또는 IP 주소로 사용량 확인
    if is_logged_in:
        user_id = session['user_id']
        user = User.query.get(user_id)
        if user:
            is_admin = is_admin_user(user.decrypted_kakao_id)
        
        usage_count = get_daily_usage(user_id=session['user_id'])
        max_usage = 10  # 로그인 사용자는 10회 제한
    else:
        usage_count = get_daily_usage(ip_address=ip_address)
        max_usage = 1   # 비로그인 사용자는 1회 제한
    
    # 관리자용 시스템 정보
    admin_info = None
    if is_admin:
        system_usage = get_system_usage()
        total_users = get_total_users_count()
        admin_info = {
            'system_usage': system_usage,
            'max_usage': MAX_SYSTEM_USAGE_PER_DAY,
            'total_users': total_users,
            'percent': min(100, int(system_usage / MAX_SYSTEM_USAGE_PER_DAY * 100))
        }
    
    # 사용량 제한 초과 확인
    if usage_count >= max_usage:
        return render_template('index.html', error="일일 사용량을 초과했습니다. 로그인하면 더 많이 사용할 수 있습니다.", is_logged_in=is_logged_in, is_admin=is_admin, admin_info=admin_info)
    
    # GET 요청에서도 URL을 가져올 수 있도록 수정
    if request.method == 'POST':
        url = request.form.get('youtube_url')
    else:
        url = request.args.get('youtube_url')
    
    if not url:
        return render_template('index.html', error="YouTube URL을 입력해주세요.", is_logged_in=is_logged_in, is_admin=is_admin, admin_info=admin_info)
    
    # 로그인한 경우 기존 분석 결과 확인
    if is_logged_in:
        existing_data = get_video_analysis_by_url(session['user_id'], url)
        if existing_data:
            print(f"기존 분석 결과 사용: {url}")
            return render_template('index.html', video_data=existing_data, is_logged_in=is_logged_in, is_admin=is_admin, admin_info=admin_info)
    
    # YouTube 데이터 가져오기
    youtube_data = get_youtube_data(url)
    
    # 오류 확인
    if "error" in youtube_data:
        return render_template('index.html', error=youtube_data["error"], is_logged_in=is_logged_in, is_admin=is_admin, admin_info=admin_info)
    
    # 필요한 데이터 추출
    video_data = extract_video_data(youtube_data)
    
    # 시스템 사용량 증가
    system_usage = increment_system_usage()
    if is_admin:
        admin_info = {
            'system_usage': system_usage,
            'max_usage': MAX_SYSTEM_USAGE_PER_DAY,
            'total_users': get_total_users_count(),
            'percent': min(100, int(system_usage / MAX_SYSTEM_USAGE_PER_DAY * 100))
        }
    
    # 사용량 증가
    if is_logged_in:
        increment_daily_usage(user_id=session['user_id'], ip_address=ip_address)
    else:
        increment_daily_usage(ip_address=ip_address)
    
    # 로그인한 경우 분석 기록 저장
    if is_logged_in:
        try:
            # 사용 로그 저장
            log = UsageLog(
                user_id=session['user_id'],
                url=url,
                video_id=video_data.get('id', ''),
                video_title=video_data.get('title', ''),
                timestamp=datetime.now()
            )
            db.session.add(log)
            db.session.commit()
            
            # 분석 결과 저장
            save_video_analysis(
                user_id=session['user_id'],
                log_id=log.id,
                video_id=video_data.get('id', ''),
                data=json.dumps(video_data)
            )
            
            print(f"분석 기록 저장 완료: {log.id}")
        except Exception as e:
            print(f"분석 기록 저장 오류: {str(e)}")
            db.session.rollback()
    
    return render_template('index.html', video_data=video_data, is_logged_in=is_logged_in, is_admin=is_admin, admin_info=admin_info)

# 카카오 로그인 라우트
@flask_app.route('/login/kakao')
def kakao_login():
    # 카카오 로그인 URL 생성
    kakao_auth_url = f"https://kauth.kakao.com/oauth/authorize?client_id={KAKAO_REST_API_KEY}&redirect_uri={KAKAO_REDIRECT_URI}&response_type=code"
    
    # 카카오 로그인 페이지로 리다이렉트
    return redirect(kakao_auth_url)

# 카카오 로그인 콜백 라우트
@flask_app.route('/login/kakao/callback')
def kakao_callback():
    try:
        # 오류 파라미터 확인
        error = request.args.get('error')
        if error:
            print(f"카카오 로그인 오류: {error}")
            return redirect(url_for('index', error=f"카카오 로그인 오류: {error}"))
        
        # 인증 코드 가져오기
        code = request.args.get('code')
        if not code:
            return redirect(url_for('index', error="인증 코드를 받지 못했습니다."))
        
        # 토큰 요청 URL
        token_url = "https://kauth.kakao.com/oauth/token"
        
        # 토큰 요청 데이터
        data = {
            'grant_type': 'authorization_code',
            'client_id': KAKAO_REST_API_KEY,
            'client_secret': KAKAO_CLIENT_SECRET,
            'redirect_uri': KAKAO_REDIRECT_URI,
            'code': code
        }
        
        # 토큰 요청
        token_response = requests.post(token_url, data=data)
        
        # 토큰 요청 실패 시 홈페이지로 리다이렉트
        if token_response.status_code != 200:
            print(f"토큰 요청 실패: {token_response.status_code}, {token_response.text}")
            return redirect(url_for('index', error="토큰 요청에 실패했습니다."))
        
        # 토큰 정보 가져오기
        token_info = token_response.json()
        access_token = token_info.get('access_token')
        
        # 사용자 정보 요청 URL
        user_info_url = "https://kapi.kakao.com/v2/user/me"
        
        # 사용자 정보 요청 헤더
        headers = {
            'Authorization': f"Bearer {access_token}"
        }
        
        # 사용자 정보 요청
        user_info_response = requests.get(user_info_url, headers=headers)
        
        # 사용자 정보 요청 실패 시 홈페이지로 리다이렉트
        if user_info_response.status_code != 200:
            print(f"사용자 정보 요청 실패: {user_info_response.status_code}, {user_info_response.text}")
            return redirect(url_for('index', error="사용자 정보 요청에 실패했습니다."))
        
        # 사용자 정보 가져오기
        user_info = user_info_response.json()
        print(f"사용자 정보: {json.dumps(user_info, indent=2)}")
        kakao_id = str(user_info.get('id'))
        nickname = user_info.get('properties', {}).get('nickname')
        
        # 데이터베이스 연결 확인
        try:
            db.session.execute("SELECT 1")
        except Exception as db_error:
            print(f"데이터베이스 연결 오류: {str(db_error)}")
            return redirect(url_for('index', error="데이터베이스 연결에 실패했습니다."))
        
        # 사용자 조회 또는 생성
        user = get_user_by_kakao_id(kakao_id)
        print(f"기존 사용자 조회 결과: {user}")
        if not user:
            print(f"새 사용자 생성: {kakao_id}, {nickname}")
            user = create_user(kakao_id, nickname)
        
        # 세션에 사용자 정보 저장
        session['user_id'] = user.id
        session['nickname'] = user.decrypted_nickname
    except Exception as e:
        print(f"카카오 로그인 처리 중 오류 발생: {str(e)}")
        import traceback
        traceback.print_exc()
        
        # 오류 메시지 상세화
        error_message = str(e)
        if "no such column" in error_message:
            error_message = "데이터베이스 스키마 오류입니다. 관리자에게 문의하세요."
        
        return redirect(url_for('index', error=f"로그인 처리 중 오류가 발생했습니다: {error_message}"))
    
    # 홈페이지로 리다이렉트
    return redirect(url_for('index'))

# 로그아웃 라우트
@flask_app.route('/logout')
def logout_route():
    # 세션에서 사용자 정보 삭제
    session.pop('user_id', None)
    session.pop('nickname', None)
    
    # 홈페이지로 리다이렉트
    return redirect(url_for('index'))

# 사용자 기록 조회 라우트
@flask_app.route('/my-history')
def my_history():
    # 로그인 확인
    if 'user_id' not in session:
        return redirect(url_for('index', error="로그인이 필요한 서비스입니다."))
    
    # 사용자 ID 가져오기
    user_id = session['user_id']
    
    # 사용자 기록 조회
    logs = get_user_logs(user_id, limit=3)
    
    # 비디오 정보 가져오기
    history_items = []
    for log in logs:
        # 기본 정보
        item = {
            'id': log.id,
            'url': log.url,
            'video_id': log.video_id,
            'title': log.video_title or f"비디오 {log.video_id}",
            'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        history_items.append(item)
    
    # 템플릿 렌더링
    return render_template('history.html', history_items=history_items)

# 사용자 기록 삭제 라우트
@flask_app.route('/delete-history/<int:log_id>', methods=['POST'])
def delete_history(log_id):
    # 로그인 확인
    if 'user_id' not in session:
        return jsonify({"error": "로그인이 필요합니다."}), 401
    
    # 사용자 ID 가져오기
    user_id = session['user_id']
    
    try:
        # 로그 조회
        log = UsageLog.query.filter_by(id=log_id, user_id=user_id).first()
        
        # 로그가 없거나 다른 사용자의 로그인 경우
        if not log:
            return jsonify({"error": "기록을 찾을 수 없습니다."}), 404
        
        # 로그 삭제
        db.session.delete(log)
        db.session.commit()
        
        return jsonify({"success": True}), 200
    except Exception as e:
        print(f"기록 삭제 오류: {str(e)}")
        return jsonify({"error": "기록 삭제 중 오류가 발생했습니다."}), 500

# 저장된 분석 결과 보기 라우트
@flask_app.route('/view-analysis/<int:log_id>')
def view_analysis(log_id):
    # 로그인 확인
    if 'user_id' not in session:
        return redirect(url_for('index', error="로그인이 필요한 서비스입니다."))
    
    # 사용자 ID 가져오기
    user_id = session['user_id']
    
    # 관리자 확인
    user = User.query.get(user_id)
    is_admin = False
    if user:
        is_admin = is_admin_user(user.decrypted_kakao_id)
    
    try:
        # 로그 조회
        log = UsageLog.query.filter_by(id=log_id, user_id=user_id).first()
        if not log:
            return redirect(url_for('my_history', error="기록을 찾을 수 없습니다."))
        
        # 분석 결과 조회
        video_data = get_video_analysis(log_id)
        if not video_data:
            # 분석 결과가 없으면 다시 분석
            return redirect(url_for('fetch_youtube_data', youtube_url=log.url))
        
        # 관리자용 시스템 정보
        admin_info = None
        if is_admin:
            system_usage = get_system_usage()
            total_users = get_total_users_count()
            admin_info = {
                'system_usage': system_usage,
                'max_usage': MAX_SYSTEM_USAGE_PER_DAY,
                'total_users': total_users,
                'percent': min(100, int(system_usage / MAX_SYSTEM_USAGE_PER_DAY * 100))
            }
        
        # 결과 페이지 렌더링
        return render_template('index.html', video_data=video_data, is_logged_in=True, is_admin=is_admin, admin_info=admin_info)
    except Exception as e:
        print(f"분석 결과 조회 오류: {str(e)}")
        import traceback
        traceback.print_exc()
        return redirect(url_for('my_history', error="분석 결과 조회 중 오류가 발생했습니다."))

if __name__ == '__main__':
    # 환경 변수에서 포트 가져오기 (없으면 7777 사용)
    port = int(os.environ.get('PORT', 7777))
    flask_app.run(host='0.0.0.0', port=port, debug=True) 