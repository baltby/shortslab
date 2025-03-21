from app import flask_app
from database import db, User, encrypt_data
import os

def migrate_users():
    """기존 사용자 데이터를 암호화하여 마이그레이션합니다."""
    with flask_app.app_context():
        # 모든 사용자 조회
        users = User.query.all()
        
        for user in users:
            # 암호화되지 않은 데이터인지 확인
            try:
                # 이미 암호화된 데이터는 복호화 시도 시 오류가 발생하지 않음
                decrypt_data(user.kakao_id)
                print(f"사용자 {user.id}는 이미 암호화되어 있습니다.")
                continue
            except:
                # 암호화되지 않은 데이터 암호화
                print(f"사용자 {user.id} 암호화 중...")
                user.kakao_id = encrypt_data(user.kakao_id)
                if user.nickname:
                    user.nickname = encrypt_data(user.nickname)
                if user.profile_image:
                    user.profile_image = encrypt_data(user.profile_image)
        
        # 변경사항 저장
        db.session.commit()
        print("사용자 데이터 암호화 완료")

if __name__ == "__main__":
    migrate_users() 