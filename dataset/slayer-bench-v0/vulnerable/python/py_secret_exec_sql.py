import sqlite3
import subprocess
API_KEY = "sk-prod-abc123secretkey9999"

def search(query):
    cursor = sqlite3.connect("db.sqlite3").cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{query}'")
    return cursor.fetchall()

def analyze(filename):
    return subprocess.run(f"analyze {filename}", shell=True, capture_output=True)
