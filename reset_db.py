import os
from app import flask_app
from database import db

def reset_database():
    """데이터베이스를 초기화합니다."""
    with flask_app.app_context():
        # 데이터베이스 파일 경로
        db_path = 'users.db'
        
        # 파일이 존재하면 삭제
        if os.path.exists(db_path):
            os.remove(db_path)
            print(f"기존 데이터베이스 파일 '{db_path}' 삭제됨")
        
        # 새 데이터베이스 생성
        db.create_all()
        print("새 데이터베이스 생성 완료")

if __name__ == "__main__":
    reset_database() 