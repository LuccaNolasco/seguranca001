import sqlite3
import hashlib

# ============================================================
# CENÁRIO B: Senha com Hash MD5 — MELHOR QUE NADA, MAS FRÁGIL
# ============================================================
# O MD5 transforma a senha num "resumo" de 32 caracteres hexadecimais.
# Parece seguro, mas hoje em dia existem bases ENORMES de hashes MD5 já calculados
# (rainbow tables). Sites como crackstation.net revertem hashes MD5 em milissegundos.
# Além disso, duas pessoas com a MESMA senha geram o MESMO hash —
# isso é um problema sério porque um atacante pode identificar senhas repetidas.

def hash_md5(password):
    # MD5 gera sempre 128 bits (32 hex chars) — rápido demais pro nosso bem
    return hashlib.md5(password.encode()).hexdigest()

def registrar(username, password):
    senha_hash = hash_md5(password)

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # Guarda o hash, não a senha original. Mas MD5 é "quebrável" hoje.
    cursor.execute("""
    INSERT INTO usuarios (username, password, method)
    VALUES (?, ?, 'md5')
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
