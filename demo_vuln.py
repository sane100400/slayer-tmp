from flask import Flask, request, redirect, make_response
import sqlite3
import hashlib
import subprocess
import os

app = Flask(__name__)

# 하드코딩된 시크릿 키
SECRET_KEY = "super_secret_key_1234"
DB_PASSWORD = "admin123"
API_KEY = "sk-prod-abc123secretkey9999xxxx"

DEBUG = True


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]

    # MD5 해시로 비밀번호 검증 (취약)
    hashed = hashlib.md5(password.encode()).hexdigest()

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # SQL Injection 취약점
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}' AND password = '{hashed}'")
    user = cursor.fetchone()

    if user:
        resp = make_response(redirect("/dashboard"))
        # 보안 옵션 없는 쿠키
        resp.set_cookie("session_token", "abc123xyz")
        return resp
    return "로그인 실패", 401


@app.route("/search")
def search():
    query = request.args.get("q", "")
    conn = sqlite3.connect("users.db")
    # SQL Injection 취약점 (% 포맷)
    sql = "SELECT * FROM products WHERE name LIKE '%%%s%%'" % query
    conn.execute(sql)
    return "ok"


@app.route("/run_report")
def run_report():
    filename = request.args.get("file")
    # Command Injection 취약점
    output = subprocess.run(f"python reports/{filename}", shell=True, capture_output=True)
    return output.stdout


@app.route("/callback")
def callback():
    next_url = request.args.get("next", "/")
    # Open Redirect 취약점
    return redirect(request.args.get("next"))


if __name__ == "__main__":
    # Debug 모드 켜진 채 배포
    app.run(debug=True, host="0.0.0.0")
