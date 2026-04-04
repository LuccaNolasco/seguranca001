import sqlite3
import hashlib
import os

def gerar_salt():

    return os.urandom(16).hex()

def hash_senha(password, salt):

    texto = password + salt
    return hashlib.sha256(texto.encode()).hexdigest()

def registrar(username, password):

    salt = gerar_salt()

    senha_hash = hash_senha(password, salt)

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO usuarios (username, password, salt)
    VALUES (?, ?, ?)
    """, (username, senha_hash, salt))

    conn.commit()
    conn.close()

def login(username, password):

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT password, salt
    FROM usuarios
    WHERE username=?
    """, (username,))

    result = cursor.fetchone()

    if result:

        senha_bd, salt = result

        senha_hash = hash_senha(password, salt)

        return senha_hash == senha_bd

    return False
