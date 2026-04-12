import sqlite3
import hashlib
import os

# ============================================================
# CENÁRIO C: Hash SHA-256 + Salt — EVOLUÇÃO SIGNIFICATIVA
# ============================================================
# O "salt" é um valor aleatório gerado para CADA usuário.
# Antes de fazer o hash, a gente concatena a senha com o salt.
# Resultado: mesmo que dois usuários tenham a senha "123456",
# os hashes serão COMPLETAMENTE diferentes (porque os salts são diferentes).
# Isso destrói a eficácia de rainbow tables — o atacante precisaria
# gerar uma tabela inteira pra CADA salt, o que é inviável.
# Porém, SHA-256 ainda é rápido demais — um atacante com GPU
# consegue testar bilhões de combinações por segundo.

def gerar_salt():
    # 16 bytes aleatórios = 32 caracteres hex — imprevisível o suficiente
    return os.urandom(16).hex()

def hash_senha(password, salt):
    # Concatena senha + salt e aplica SHA-256 (256 bits = 64 hex chars)
    texto = password + salt
    return hashlib.sha256(texto.encode()).hexdigest()

def registrar(username, password):
    salt = gerar_salt()
    senha_hash = hash_senha(password, salt)

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # Aqui guardamos TANTO o hash quanto o salt — o salt não é segredo,
    # ele só existe pra garantir unicidade dos hashes
    cursor.execute("""
    INSERT INTO usuarios (username, password, salt, method)
    VALUES (?, ?, ?, 'salt')
    """, (username, senha_hash, salt))

    conn.commit()
    conn.close()

def login(username, password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # Busca o salt do usuário pra recalcular o hash na hora do login
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
