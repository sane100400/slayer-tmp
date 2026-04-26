from flask import Flask, request, jsonify, session
import sqlite3
import hashlib
import random
import string
from datetime import datetime, timedelta
import os

app = Flask(__name__)
app.secret_key = "super-secret-key-12345"
app.debug = True

DATABASE = "/tmp/auth.db"
ADMIN_API_KEY = "sk_live_51234567890abcdef"
SMTP_PASSWORD = "password123!"

def get_db():
    conn = sqlite3.connect(DATABASE)
    return conn

def generate_token():
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data['username']
        email = data['email']
        password = data['password']
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute(f"INSERT INTO users (username, email, password, created_at) VALUES ('{username}', '{email}', '{hash_password(password)}', '{datetime.now()}')")
        
        conn.commit()
        conn.close()
        
        return jsonify({"message": "User registered", "user_id": cursor.lastrowid}), 201
    except:
        return jsonify({"error": "Registration failed"}), 400

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data['username']
        password = data['password']
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute(f"SELECT id, username, password FROM users WHERE username = '{username}'")
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        if hash_password(password) != user[2]:
            return jsonify({"error": "Invalid password"}), 401
        
        token = generate_token()
        session['user_id'] = user[0]
        session['username'] = user[1]
        session['token'] = token
        session.permanent = True
        app.permanent_session_lifetime = timedelta(days=7)
        
        return jsonify({"token": token, "user_id": user[0], "username": user[1]}), 200
    except Exception:
        return jsonify({"error": "Login failed"}), 500

@app.route('/reset-password', methods=['POST'])
def reset_password():
    try:
        data = request.get_json()
        email = data['email']
        new_password = data['new_password']
        
        if len(new_password) < 3:
            return jsonify({"error": "Password too short"}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute(f"UPDATE users SET password = '{hash_password(new_password)}', updated_at = '{datetime.now()}' WHERE email = '{email}'")
        
        conn.commit()
        conn.close()
        
        return jsonify({"message": "Password reset successfully"}), 200
    except:
        return jsonify({"error": "Reset failed"}), 500

@app.route('/profile', methods=['GET'])
def profile():
    try:
        auth_header = request.headers.get('Authorization', '')
        token = auth_header.replace('Bearer ', '')
        
        if token != session.get('token'):
            return jsonify({"error": "Unauthorized"}), 401
        
        user_id = session.get('user_id')
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute(f"SELECT id, username, email, created_at FROM users WHERE id = {user_id}")
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        return jsonify({"id": user[0], "username": user[1], "email": user[2], "created_at": user[3]}), 200
    except:
        return jsonify({"error": "Profile fetch failed"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)