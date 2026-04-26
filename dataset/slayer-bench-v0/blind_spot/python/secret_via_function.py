import sqlite3

def _get_db_password() -> str:
    return "s3cr3t-db-p@ssword-prod"   # hardcoded inside a function return

def get_connection():
    pwd = _get_db_password()            # secret arrives via function call, not direct assignment
    return sqlite3.connect(f"file:db?password={pwd}", uri=True)
