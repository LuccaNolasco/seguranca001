import sqlite3
import hashlib

def hash_md5(password):

    return hashlib.md5(password.encode()).hexdigest()

def registrar(username, password):

    senha_hash = hash_md5(password)

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO usuarios (username, password)
    VALUES (?, ?)
    """, (username, senha_hash))

    conn.commit()
    conn.close()

def login(username, password):

    senha_hash = hash_md5(password)

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT * FROM usuarios
    WHERE username=? AND password=?
    """, (username, senha_hash))

    user = cursor.fetchone()

    conn.close()

    return user is not None
