from datetime import datetime, date, timedelta
from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet
from config import ENCRYPTION_KEY, MAX_USAGE_PER_DAY
import os
import base64
import json

# 암호화 키 생성 또는 로드
def get_encryption_key():
    key = ENCRYPTION_KEY
    if not key:
        # 환경 변수에 키가 없으면 파일에서 로드
        key_file = os.path.join(os.path.dirname(__file__), '.encryption_key')
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                key = f.read().decode('utf-8')
        else:
            # 새 키 생성
            key = Fernet.generate_key().decode('utf-8')
            # 키 파일 저장
            with open(key_file, 'wb') as f:
                f.write(key.encode('utf-8'))
            # 파일 권한 설정 (소유자만 읽기/쓰기 가능)
            os.chmod(key_file, 0o600)
    return key

# 암호화 객체 생성
cipher_suite = Fernet(get_encryption_key().encode())

# 암호화 함수
def encrypt_data(data):
    if not data:
        return None
    return cipher_suite.encrypt(data.encode('utf-8')).decode('utf-8')

# 복호화 함수
def decrypt_data(encrypted_data):
    if not encrypted_data:
        return None
    try:
        return cipher_suite.decrypt(encrypted_data.encode('utf-8')).decode('utf-8')
    except Exception as e:
        print(f"복호화 오류: {str(e)}")
        return None

# 데이터베이스 객체 초기화
db = SQLAlchemy()

# 데이터베이스 인스턴스 가져오기 함수
def get_db():
    return db

class User(db.Model):
    """사용자 모델"""
    id = db.Column(db.Integer, primary_key=True)
    kakao_id = db.Column(db.String(255), unique=True, nullable=False)  # 암호화된 카카오 ID
    nickname = db.Column(db.String(255))  # 암호화된 닉네임
    usage_count = db.Column(db.Integer, default=0)
    last_usage_date = db.Column(db.Date, default=date.today)
    
    def __init__(self, kakao_id, nickname=None):
        self.kakao_id = encrypt_data(kakao_id)
        self.nickname = encrypt_data(nickname) if nickname else None
        self.usage_count = 0
        self.last_usage_date = date.today()
    
    def check_usage_limit(self):
        """사용자의 일일 사용 제한 확인"""
        today = date.today()
        
        # 날짜가 바뀌었으면 사용 횟수 리셋
        if self.last_usage_date != today:
            self.usage_count = 0
            self.last_usage_date = today
            db.session.commit()
        
        # 사용 가능 여부 반환
        return self.usage_count < MAX_USAGE_PER_DAY
    
    def increment_usage(self):
        """사용 횟수 증가"""
        today = date.today()
        
        # 날짜가 바뀌었으면 사용 횟수 리셋
        if self.last_usage_date != today:
            self.usage_count = 0
            self.last_usage_date = today
        
        self.usage_count += 1
        db.session.commit()
        
        return self.usage_count

    # 복호화된 정보 가져오기
    @property
    def decrypted_kakao_id(self):
        return decrypt_data(self.kakao_id)
    
    @property
    def decrypted_nickname(self):
        return decrypt_data(self.nickname) if self.nickname else None

def get_user_by_kakao_id(kakao_id):
    """카카오 ID로 사용자 조회"""
    # 모든 사용자 조회 후 복호화하여 비교
    users = User.query.all()
    for user in users:
        if user.decrypted_kakao_id == kakao_id:
            return user
    return None

def create_user(kakao_id, nickname=None):
    """새 사용자 생성"""
    user = User(kakao_id, nickname)
    db.session.add(user)
    db.session.commit()
    return user

def check_non_login_usage(session):
    """비로그인 사용자의 사용 제한 확인"""
    today = date.today().isoformat()
    
    # 세션에 사용 정보가 없거나 날짜가 바뀌었으면 초기화
    if 'non_login_usage' not in session or session.get('non_login_usage_date') != today:
        session['non_login_usage'] = 0
        session['non_login_usage_date'] = today
    
    # 사용 가능 여부 반환
    return session['non_login_usage'] < 1

def increment_non_login_usage(session):
    """비로그인 사용자의 사용 횟수 증가"""
    today = date.today().isoformat()
    
    # 세션에 사용 정보가 없거나 날짜가 바뀌었으면 초기화
    if 'non_login_usage' not in session or session.get('non_login_usage_date') != today:
        session['non_login_usage'] = 0
        session['non_login_usage_date'] = today
    
    session['non_login_usage'] += 1
    return session['non_login_usage']

# 사용 로그 모델
class UsageLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    url = db.Column(db.String(200), nullable=False)
    video_id = db.Column(db.String(50))
    video_title = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.now)

# 분석 결과 모델
class VideoAnalysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    log_id = db.Column(db.Integer, db.ForeignKey('usage_log.id'), nullable=False)
    video_id = db.Column(db.String(50), nullable=False)
    data = db.Column(db.Text, nullable=False)  # JSON 형태로 저장
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    # 관계 설정
    usage_log = db.relationship('UsageLog', backref=db.backref('analysis', lazy=True))

# 일일 사용량 모델
class DailyUsage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # 로그인 사용자는 user_id 저장
    ip_address = db.Column(db.String(50), nullable=False)  # 비로그인 사용자는 IP 주소로 식별
    usage_date = db.Column(db.Date, nullable=False)
    count = db.Column(db.Integer, default=0)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    
    # 복합 인덱스 (사용자 또는 IP + 날짜)
    __table_args__ = (
        db.UniqueConstraint('user_id', 'ip_address', 'usage_date', name='uix_daily_usage'),
    )

# 시스템 사용량 모델
class SystemUsage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usage_date = db.Column(db.Date, nullable=False, unique=True)
    total_count = db.Column(db.Integer, default=0)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

def get_user_logs(user_id, limit=10):
    """사용자의 최근 분석 기록을 가져옵니다."""
    try:
        logs = UsageLog.query.filter_by(user_id=user_id).order_by(UsageLog.timestamp.desc()).limit(limit).all()
        return logs
    except Exception as e:
        print(f"사용자 로그 조회 오류: {str(e)}")
        return []

def count_user_logs(user_id):
    """사용자의 분석 기록 수를 반환합니다."""
    try:
        return UsageLog.query.filter_by(user_id=user_id).count()
    except Exception as e:
        print(f"로그 수 조회 오류: {str(e)}")
        return 0

def delete_oldest_log(user_id):
    """사용자의 가장 오래된 로그를 삭제합니다."""
    try:
        oldest_log = UsageLog.query.filter_by(user_id=user_id).order_by(UsageLog.timestamp.asc()).first()
        if oldest_log:
            db.session.delete(oldest_log)
            db.session.commit()
            return True
        return False
    except Exception as e:
        print(f"오래된 로그 삭제 오류: {str(e)}")
        return False

def get_video_title_from_db(video_id):
    """데이터베이스에서 비디오 제목을 가져옵니다."""
    try:
        log = UsageLog.query.filter_by(video_id=video_id).order_by(UsageLog.timestamp.desc()).first()
        if log and log.video_title:
            return log.video_title
        return None
    except Exception as e:
        print(f"비디오 제목 조회 오류: {str(e)}")
        return None

def save_video_analysis(user_id, log_id, video_id, data):
    """분석 결과를 저장합니다."""
    try:
        # 기존 분석 결과 확인
        existing = VideoAnalysis.query.filter_by(log_id=log_id).first()
        if existing:
            # 기존 결과 업데이트
            existing.data = data
            existing.created_at = datetime.now()
            db.session.commit()
            return existing
        
        # 새 분석 결과 저장
        analysis = VideoAnalysis(
            user_id=user_id,
            log_id=log_id,
            video_id=video_id,
            data=data
        )
        db.session.add(analysis)
        db.session.commit()
        return analysis
    except Exception as e:
        print(f"분석 결과 저장 오류: {str(e)}")
        db.session.rollback()
        return None

def get_video_analysis(log_id):
    """로그 ID로 분석 결과를 가져옵니다."""
    try:
        analysis = VideoAnalysis.query.filter_by(log_id=log_id).first()
        if analysis:
            return json.loads(analysis.data)
        return None
    except Exception as e:
        print(f"분석 결과 조회 오류: {str(e)}")
        return None

def get_video_analysis_by_url(user_id, url):
    """URL로 분석 결과를 가져옵니다."""
    try:
        # URL로 로그 찾기
        log = UsageLog.query.filter_by(user_id=user_id, url=url).order_by(UsageLog.timestamp.desc()).first()
        if not log:
            return None
        
        # 로그 ID로 분석 결과 찾기
        return get_video_analysis(log.id)
    except Exception as e:
        print(f"URL로 분석 결과 조회 오류: {str(e)}")
        return None

def get_daily_usage(user_id=None, ip_address=None):
    """사용자 또는 IP 주소의 오늘 사용량을 가져옵니다."""
    try:
        today = date.today()
        
        # 로그인 사용자
        if user_id:
            usage = DailyUsage.query.filter_by(user_id=user_id, usage_date=today).first()
        # 비로그인 사용자
        elif ip_address:
            usage = DailyUsage.query.filter_by(user_id=None, ip_address=ip_address, usage_date=today).first()
        else:
            return 0
        
        return usage.count if usage else 0
    except Exception as e:
        print(f"일일 사용량 조회 오류: {str(e)}")
        return 0

def increment_daily_usage(user_id=None, ip_address=None):
    """사용자 또는 IP 주소의 오늘 사용량을 증가시킵니다."""
    try:
        today = date.today()
        
        # 로그인 사용자
        if user_id:
            usage = DailyUsage.query.filter_by(user_id=user_id, usage_date=today).first()
            if not usage:
                usage = DailyUsage(user_id=user_id, ip_address=ip_address or '', usage_date=today, count=0)
                db.session.add(usage)
        # 비로그인 사용자
        elif ip_address:
            usage = DailyUsage.query.filter_by(user_id=None, ip_address=ip_address, usage_date=today).first()
            if not usage:
                usage = DailyUsage(user_id=None, ip_address=ip_address, usage_date=today, count=0)
                db.session.add(usage)
        else:
            return 0
        
        # 사용량 증가
        usage.count += 1
        db.session.commit()
        
        return usage.count
    except Exception as e:
        print(f"일일 사용량 증가 오류: {str(e)}")
        db.session.rollback()
        return 0

def reset_expired_usage():
    """만료된 사용량 기록을 삭제합니다 (30일 이상 지난 기록)"""
    try:
        thirty_days_ago = date.today() - timedelta(days=30)
        DailyUsage.query.filter(DailyUsage.usage_date < thirty_days_ago).delete()
        db.session.commit()
        return True
    except Exception as e:
        print(f"만료된 사용량 삭제 오류: {str(e)}")
        db.session.rollback()
        return False

def get_system_usage():
    """오늘의 전체 시스템 사용량을 가져옵니다."""
    try:
        today = date.today()
        usage = SystemUsage.query.filter_by(usage_date=today).first()
        if not usage:
            usage = SystemUsage(usage_date=today, total_count=0)
            db.session.add(usage)
            db.session.commit()
        return usage.total_count
    except Exception as e:
        print(f"시스템 사용량 조회 오류: {str(e)}")
        return 0

def increment_system_usage():
    """오늘의 전체 시스템 사용량을 증가시킵니다."""
    try:
        today = date.today()
        usage = SystemUsage.query.filter_by(usage_date=today).first()
        if not usage:
            usage = SystemUsage(usage_date=today, total_count=0)
            db.session.add(usage)
        
        usage.total_count += 1
        db.session.commit()
        return usage.total_count
    except Exception as e:
        print(f"시스템 사용량 증가 오류: {str(e)}")
        db.session.rollback()
        return 0

def check_system_usage_limit(max_limit=500):
    """시스템 사용량이 제한을 초과했는지 확인합니다."""
    try:
        total_usage = get_system_usage()
        return total_usage < max_limit
    except Exception as e:
        print(f"시스템 사용량 제한 확인 오류: {str(e)}")
        return False  # 오류 발생 시 안전하게 제한 초과로 처리

def is_admin_user(kakao_id):
    """관리자 사용자인지 확인합니다."""
    try:
        user = get_user_by_kakao_id(kakao_id)
        if not user:
            return False
        
        # 카카오 계정 정보 가져오기
        user_info_url = "https://kapi.kakao.com/v2/user/me"
        headers = {'Authorization': f"Bearer {kakao_id}"}
        
        # 이 부분은 실제로는 작동하지 않습니다. 
        # 카카오 API 호출은 app.py에서 처리하고 여기서는 간단히 이메일로 확인합니다.
        # 실제 구현에서는 사용자 테이블에 admin 필드를 추가하는 것이 좋습니다.
        return user.decrypted_kakao_id == "3922302962"  # zunestory@naver.com의 카카오 ID
    except Exception as e:
        print(f"관리자 확인 오류: {str(e)}")
        return False

def get_total_users_count():
    """전체 가입자 수를 가져옵니다."""
    try:
        return User.query.count()
    except Exception as e:
        print(f"가입자 수 조회 오류: {str(e)}")
        return 0 