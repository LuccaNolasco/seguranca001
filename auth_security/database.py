import sqlite3

def criar_banco():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        salt TEXT
    )
    """)

    conn.commit()
    conn.close()

if __name__ == "__main__":
    criar_banco()
    print("Banco criado com sucesso.")
