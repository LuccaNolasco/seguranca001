import sqlite3

def registrar(username, password):

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO usuarios (username, password)
    VALUES (?, ?)
    """, (username, password))

    conn.commit()
    conn.close()

def login(username, password):

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT * FROM usuarios
    WHERE username=? AND password=?
    """, (username, password))

    user = cursor.fetchone()

    conn.close()

    return user is not None


# TESTE

registrar("admin", "123456")

if login("admin", "123456"):
    print("Login OK")
else:
    print("Login inválido")
