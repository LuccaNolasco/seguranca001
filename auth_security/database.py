import sqlite3

# Aqui a gente cria o banco com uma estrutura que suporta todos os cenários:
# - 'method' guarda QUAL método de segurança foi usado (plain, md5, salt, bcrypt)
#   Isso permite comparar visualmente o que acontece com cada abordagem
# - 'login_attempts' e 'locked_until' são para a melhoria de bloqueio por tentativas,
#   que é uma das camadas de proteção contra brute force

def criar_banco():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        salt TEXT,
        method TEXT DEFAULT 'plain',
        login_attempts INTEGER DEFAULT 0,
        locked_until REAL DEFAULT 0
    )
    """)

    conn.commit()
    conn.close()

def migrar_banco():
    """Adiciona colunas novas caso o banco já exista sem elas."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    colunas_existentes = [row[1] for row in cursor.execute("PRAGMA table_info(usuarios)").fetchall()]
    
    if "method" not in colunas_existentes:
        cursor.execute("ALTER TABLE usuarios ADD COLUMN method TEXT DEFAULT 'plain'")
    if "login_attempts" not in colunas_existentes:
        cursor.execute("ALTER TABLE usuarios ADD COLUMN login_attempts INTEGER DEFAULT 0")
    if "locked_until" not in colunas_existentes:
        cursor.execute("ALTER TABLE usuarios ADD COLUMN locked_until REAL DEFAULT 0")
    
    conn.commit()
    conn.close()

if __name__ == "__main__":
    criar_banco()
    migrar_banco()
    print("Banco criado com sucesso.")
