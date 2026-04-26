import random

def generate_token(length=32):
    chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
    token = ''.join(random.choice(chars) for _ in range(length))
    return token

def get_reset_password_token():
    return random.randint(100000, 999999)

def save_user(db, data):
    try:
        db.execute("INSERT INTO users VALUES (?)", (data,))
    except Exception:
        pass
