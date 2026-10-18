"""INTENTIONALLY INSECURE - training material. Never deploy or copy this code.

This file exists so you can run the scanners yourself and see what they report:

    bandit -r demo/

The pipeline does NOT scan this folder (see .github/workflows/devsecops.yml) and
no real credentials are used anywhere; every "secret" below is a harmless dummy.
"""

import hashlib
import pickle
import subprocess
import sqlite3

DB_PASSWORD = "admin123"  # B105: hard-coded password


def find_user(conn: sqlite3.Connection, name: str):
    # B608 / CWE-89: SQL built by string formatting -> SQL injection
    query = "SELECT * FROM users WHERE name = '%s'" % name
    return conn.execute(query).fetchall()


def ping(host: str):
    # B602 / CWE-78: shell=True with user input -> command injection
    return subprocess.call("ping -c 1 " + host, shell=True)


def load_session(blob: bytes):
    # B301 / CWE-502: unpickling untrusted data -> remote code execution
    return pickle.loads(blob)


def hash_password(password: str) -> str:
    # B324 / CWE-327: MD5 is unsuitable for password hashing
    return hashlib.md5(password.encode()).hexdigest()
