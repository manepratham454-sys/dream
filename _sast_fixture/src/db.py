import sqlite3


def get_user(conn, user_id):
    cursor = conn.cursor()
    # Intentional SQL injection: f-string into execute()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()


def run_arithmetic(expr):
    # Intentional eval() RCE
    return eval(expr)


def load_config(blob):
    # Intentional insecure deserialisation
    import pickle
    return pickle.loads(blob)


def ping(host):
    # Intentional command injection
    import os
    os.system(f"ping {host}")


# Intentional hardcoded secrets (secret-scan should flag these)
API_TOKEN = "ghp_1234567890abcdef1234567890abcdef1aB"
AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"
STRIPE_KEY = "sk_test_4eC39HqLyjWDarjtT1zdp7dc123456"

# Intentional DEBUG=True committed
DEBUG = True
