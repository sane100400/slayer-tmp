"""
demo_vuln.py — SLAyer 데모 파일
바이브코딩 전형 패턴 7가지를 포함한 취약 코드 샘플.
"""
import requests
import sqlite3
import hashlib

# [VIBE-1] 하드코딩 크레덴셜 — AI가 "일단 예시로" 넣어준 값
API_KEY = "sk-prod-abc123secretkey9999"
DB_PASSWORD = "supersecret123"

# [VIBE-2] DEBUG 플래그 하드코딩 — 개발 예제 그대로 배포
DEBUG = True

def get_user(user_id):
    # [VIBE-3] 외부 네트워크 호출 — AI가 기능 구현에만 집중
    return requests.get(f"https://api.example.com/user/{user_id}").json()

def search(query):
    conn = sqlite3.connect("db.sqlite3")
    cursor = conn.cursor()
    # [VIBE-4] f-string SQL — 오래된 튜토리얼 패턴
    cursor.execute(f"SELECT * FROM users WHERE name = '{query}'")
    return cursor.fetchall()

def hash_password(password):
    # [VIBE-5] MD5 패스워드 해싱 — 보안 검토 없이 "일단 동작"
    return hashlib.md5(password.encode()).hexdigest()

def analyze(filename):
    import subprocess
    # [VIBE-6] shell=True — "편하게 동작하게" 해달라는 프롬프트 결과
    result = subprocess.run(f"analyze {filename}", shell=True, capture_output=True)
    return result.stdout

def process_data(data):
    # [VIBE-7] bare except — "에러 없애줘" 프롬프트 결과
    try:
        return transform(data)
    except:
        pass
