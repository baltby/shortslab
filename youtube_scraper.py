import requests
import json
from urllib.parse import urlparse, parse_qs
from youtube_transcript_api import YouTubeTranscriptApi
import re
from config import USE_PROXY, PROXY_USERNAME, PROXY_PASSWORD, PROXY_HOST, PROXY_PORT
import os
import random

def get_proxy_settings():
    """프록시 설정 가져오기"""
    if not USE_PROXY:
        return None
    
    # 여러 포트 중 하나를 랜덤하게 선택
    available_ports = ["10001", "10002", "10003", "10004", "10005", "10006", "10007", "10008"]
    selected_port = random.choice(available_ports)
    
    proxy_auth = f"{PROXY_USERNAME}:{PROXY_PASSWORD}"
    proxies = {
        "http": f"http://{proxy_auth}@{PROXY_HOST}:{selected_port}",
        "https": f"https://{proxy_auth}@{PROXY_HOST}:{selected_port}"
    }
    print(f"Using proxy port: {selected_port}")
    return proxies

def extract_video_id(url):
    """URL에서 비디오 ID 추출"""
    # 숏폼 URL 처리
    if '/shorts/' in url:
        video_id = url.split('/shorts/')[1].split('?')[0]
        return video_id

    # 일반 유튜브 URL 처리
    parsed_url = urlparse(url)
    if parsed_url.netloc == 'youtu.be':
        return parsed_url.path.lstrip('/')

    if parsed_url.netloc in ('www.youtube.com', 'youtube.com'):
        query_params = parse_qs(parsed_url.query)
        if 'v' in query_params:
            return query_params['v'][0]

    # 비디오 ID를 찾을 수 없는 경우
    raise ValueError("유효한 YouTube URL이 아닙니다.")

def convert_to_long_form(url):
    """숏폼 URL을 롱폼 URL로 변환"""
    if '/shorts/' in url:
        video_id = url.split('/shorts/')[1].split('?')[0]
        return f"https://www.youtube.com/watch?v={video_id}"
    return url

def get_youtube_data(url):
    """YouTube 비디오 데이터 가져오기"""
    try:
        # URL에서 비디오 ID 추출
        video_id = extract_video_id(url)

        # 비디오 기본 정보 가져오기 (YouTube oEmbed API 사용)
        oembed_url = f"https://www.youtube.com/oembed?url=https://www.youtube.com/watch?v={video_id}&format=json"
        proxies = get_proxy_settings()
        if proxies:
            os.environ['http_proxy'] = proxies['http']
            os.environ['https_proxy'] = proxies['https']
        oembed_response = requests.get(oembed_url, proxies=proxies)
        oembed_response.raise_for_status()
        oembed_data = oembed_response.json()

        # 비디오 자막 가져오기
        try:
            transcript_entries = YouTubeTranscriptApi.get_transcript(video_id, languages=['ko', 'en'])
            transcript_text = " ".join([entry["text"] for entry in transcript_entries])
        except Exception as e:
            print(f"자막 가져오기 오류: {str(e)}")
            transcript_text = "자막을 찾을 수 없습니다."

        # 채널 ID 추출 (썸네일 URL에서)
        thumbnail_url = f"https://img.youtube.com/vi/{video_id}/maxresdefault.jpg"

        # 결과 데이터 구성
        result = [{
            "id": video_id,
            "title": oembed_data.get("title", "제목 없음"),
            "url": f"https://www.youtube.com/watch?v={video_id}",
            "thumbnailUrl": thumbnail_url,
            "channelName": oembed_data.get("author_name", ""),
            "channelUrl": oembed_data.get("author_url", ""),
            "subtitles": [{"plaintext": transcript_text}]
        }]

        return result
    except ValueError as e:
        print(f"URL 파싱 오류: {str(e)}")
        return {"error": "올바른 YouTube URL이 아닙니다."}
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

        # 프록시 설정
        proxies = get_proxy_settings()
        if proxies:
            os.environ['http_proxy'] = proxies['http']
            os.environ['https_proxy'] = proxies['https']

        # 데이터베이스에 없으면 YouTube API로 가져오기
        url = f"https://www.youtube.com/watch?v={video_id}"
        data = get_youtube_data(url)
        if "error" not in data and data and len(data) > 0:
            return data[0].get("title", f"비디오 {video_id}")

        return f"비디오 {video_id}"
    except Exception as e:
        print(f"비디오 제목 가져오기 오류: {str(e)}")
        return f"비디오 {video_id}"