"""
demo_vuln.py - vulnerable SLAyer demo file
Sample with seven web service risk patterns from spec.md.
"""
import random
import requests
import sqlite3
import subprocess

API_KEY = "sk-prod-abc123secretkey9999"
DB_PASSWORD = "supersecret123"
DEBUG = True


def proxy_user(user_id: str):
    return requests.get(f"https://api.example.com/user/{user_id}").json()


def search(query: str):
    conn = sqlite3.connect("db.sqlite3")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{query}'")
    return cursor.fetchall()


def analyze(filename: str):
    return subprocess.run(f"analyze {filename}", shell=True, capture_output=True)


def generate_reset_token() -> str:
    alphabet = "abcdef0123456789"
    return "".join(random.choice(alphabet) for _ in range(32))


def process_data(data):
    try:
        return transform(data)
    except:
        pass
