import sqlite3
import bcrypt

def registrar(username, password):

    senha_bytes = password.encode()

    salt = bcrypt.gensalt()

    senha_hash = bcrypt.hashpw(senha_bytes, salt)

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO usuarios (username, password)
    VALUES (?, ?)
    """, (username, senha_hash))

    conn.commit()
    conn.close()

def login(username, password):

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT password
    FROM usuarios
    WHERE username=?
    """, (username,))

    result = cursor.fetchone()

    conn.close()

    if result:

        senha_hash = result[0]

        return bcrypt.checkpw(
            password.encode(),
            senha_hash
        )

    return False
