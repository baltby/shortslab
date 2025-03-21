import requests
import json
from config import APIFY_TOKEN, APIFY_BASE_URL, APIFY_ACTOR_ID

def convert_to_long_form(url):
    """숏폼 URL을 롱폼 URL로 변환"""
    if '/shorts/' in url:
        video_id = url.split('/shorts/')[1].split('?')[0]
        return f"https://www.youtube.com/watch?v={video_id}"
    return url

def get_youtube_data(url):
    """Apify API를 호출하여 YouTube 데이터 가져오기"""
    # URL을 롱폼으로 변환
    long_form_url = convert_to_long_form(url)
    
    # Apify API 직접 호출 URL (액터 직접 실행)
    actor_id_encoded = APIFY_ACTOR_ID.replace('/', '~')
    api_url = f"{APIFY_BASE_URL}/acts/{actor_id_encoded}/runs"
    
    # 입력 JSON 구성
    input_json = {
        "downloadSubtitles": True,
        "preferAutoGeneratedSubtitles": True,
        "startUrls": [
            {
                "url": long_form_url,
                "method": "GET"
            }
        ],
        "subtitlesFormat": "plaintext",
        "subtitlesLanguage": "any"
    }
    
    try:
        # API 직접 호출 (비동기 실행)
        # 디버그 정보는 로그에만 기록
        print(f"API 호출 시작: {long_form_url}")
        
        # 헤더 설정
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {APIFY_TOKEN}"
        }
        
        # API 호출
        response = requests.post(
            api_url,
            headers=headers, 
            json=input_json,
            timeout=60  # 타임아웃 60초로 설정
        )
        
        # 디버그 정보는 로그에만 기록
        print(f"API 응답 상태: {response.status_code}")
        
        # 응답 확인
        response.raise_for_status()
        
        # 실행 ID 가져오기
        run_id = response.json()["data"]["id"]
        print(f"실행 ID: {run_id}")
        
        # 실행 완료 대기
        status_url = f"{APIFY_BASE_URL}/acts/{actor_id_encoded}/runs/{run_id}"
        
        # 최대 120초(2분) 동안 대기
        for _ in range(24):  # 5초 간격으로 24번 = 120초
            # 5초 대기
            import time
            time.sleep(5)
            
            # 상태 확인
            status_response = requests.get(
                status_url,
                headers={"Authorization": f"Bearer {APIFY_TOKEN}"},
                timeout=30
            )
            
            # 응답 확인
            if status_response.status_code != 200:
                print(f"상태 확인 오류: {status_response.status_code}")
                continue
            
            # 상태 확인
            status = status_response.json()["data"]["status"]
            print(f"실행 상태: {status}")
            
            # 완료 확인
            if status == "SUCCEEDED":
                break
            
            # 실패 확인
            if status in ["FAILED", "ABORTED", "TIMED_OUT"]:
                return {"error": "영상 정보를 가져오는 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요."}
        
        # 데이터셋 ID 가져오기
        dataset_id = status_response.json()["data"]["defaultDatasetId"]
        print(f"데이터셋 ID: {dataset_id}")
        
        # 데이터셋 항목 가져오기
        dataset_url = f"{APIFY_BASE_URL}/datasets/{dataset_id}/items"
        dataset_response = requests.get(
            dataset_url,
            headers={"Authorization": f"Bearer {APIFY_TOKEN}"},
            timeout=30
        )
        
        print(f"데이터셋 응답 상태: {dataset_response.status_code}")
        
        # 응답 확인
        dataset_response.raise_for_status()
        
        # 결과 데이터 반환
        return dataset_response.json()
    except requests.exceptions.RequestException as e:
        print(f"API 호출 오류: {str(e)}")
        return {"error": "영상 정보를 가져오는 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요."}
    except json.JSONDecodeError as e:
        print(f"JSON 파싱 오류: {str(e)}")
        return {"error": "영상 정보를 처리하는 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요."}
    except Exception as e:
        print(f"예상치 못한 오류: {str(e)}")
        import traceback
        traceback.print_exc()
        return {"error": "영상 정보를 처리하는 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요."}

def extract_video_data(data):
    """API 응답에서 필요한 비디오 데이터 추출"""
    if "error" in data:
        return data
    
    if not data or len(data) == 0:
        return {"error": "비디오 데이터를 찾을 수 없습니다."}
    
    video = data[0]  # 첫 번째 결과 사용
    
    # 자막 처리
    subtitles_text = "자막을 찾을 수 없습니다."
    if video.get("subtitles") and len(video["subtitles"]) > 0:
        for subtitle in video["subtitles"]:
            if subtitle.get("plaintext"):
                subtitles_text = subtitle["plaintext"]
                break
    
    # 필요한 데이터 추출
    return {
        "title": video.get("title", "제목 없음"),
        "id": video.get("id", ""),
        "url": video.get("url", ""),
        "thumbnailUrl": video.get("thumbnailUrl", ""),
        "viewCount": video.get("viewCount", 0),
        "likes": video.get("likes", 0),
        "commentsCount": video.get("commentsCount", 0),
        "channelName": video.get("channelName", ""),
        "channelUrl": video.get("channelUrl", ""),
        "duration": video.get("duration", ""),
        "date": video.get("date", ""),
        "text": video.get("text", "설명 없음"),
        "hashtags": video.get("hashtags", []),
        "subtitles": subtitles_text
    }

def get_video_title_from_id(video_id):
    """비디오 ID로 제목을 가져옵니다."""
    try:
        # 데이터베이스에서 제목 조회 시도
        from database import get_video_title_from_db
        title = get_video_title_from_db(video_id)
        if title:
            return title
        
        # 데이터베이스에 없으면 YouTube API로 가져오기
        url = f"https://www.youtube.com/watch?v={video_id}"
        data = get_youtube_data(url)
        if "error" not in data and data and len(data) > 0:
            return data[0].get("title", f"비디오 {video_id}")
        
        return f"비디오 {video_id}"
    except Exception as e:
        print(f"비디오 제목 가져오기 오류: {str(e)}")
        return f"비디오 {video_id}"