import os
import sqlite3
import subprocess
API_KEY = os.environ.get("API_KEY", "")

def search(query):
    cursor = sqlite3.connect("db.sqlite3").cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (query,))
    return cursor.fetchall()

def analyze(filename):
    return subprocess.run(["analyze", filename], shell=False, capture_output=True)
