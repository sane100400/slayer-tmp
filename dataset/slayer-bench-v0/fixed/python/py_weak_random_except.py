import secrets
import logging

logger = logging.getLogger(__name__)

def generate_token(length=32):
    return secrets.token_hex(length)

def get_reset_password_token():
    return secrets.randbelow(10**6)

def save_user(db, data):
    try:
        db.execute("INSERT INTO users VALUES (?)", (data,))
    except Exception as e:
        logger.warning('Failed to save user: %s', e, exc_info=True)
        raise
