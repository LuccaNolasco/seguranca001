import sqlite3

# ============================================================
# CENÁRIO A: Senha em Texto Puro (Plain Text) — O PIOR CENÁRIO
# ============================================================
# Aqui a senha é guardada EXATAMENTE como o usuário digitou.
# Se alguém tiver acesso ao banco de dados (vazamento, SQL injection, backup roubado),
# todas as senhas ficam expostas instantaneamente.
# É como guardar a chave da sua casa debaixo do tapete — qualquer um que olhe, encontra.

def registrar(username, password):
    # A senha vai direto pro banco, sem NENHUMA proteção.
    # Qualquer SELECT mostra tudo: admin | 123456
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO usuarios (username, password, method)
    VALUES (?, ?, 'plain')
    """, (username, password))

    conn.commit()
    conn.close()

def login(username, password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # Comparação direta — a senha viaja em texto puro até o banco
    cursor.execute("""
    SELECT * FROM usuarios
    WHERE username=? AND password=?
    """, (username, password))

    user = cursor.fetchone()
    conn.close()
    return user is not None
