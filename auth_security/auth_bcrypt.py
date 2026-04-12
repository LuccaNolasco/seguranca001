import sqlite3
import bcrypt

# ============================================================
# CENÁRIO D: Bcrypt — O PADRÃO OURO PARA SENHAS
# ============================================================
# Bcrypt foi PROJETADO especificamente para armazenar senhas.
# Ele tem três métodos:
#   1. Salt automático — cada hash já inclui um salt único embutido
#   2. Lentidão proposital — o "cost factor" controla quantas vezes
#      o algoritmo roda internamente (padrão: 12 rounds = 2^12 iterações)
#   3. Resistência a GPU — diferente de MD5/SHA que GPUs aceleram fácil,
#      bcrypt usa muita memória, o que dificulta ataques paralelos
# Na prática: enquanto MD5 processa bilhões de hashes/segundo,
# bcrypt processa apenas algumas DEZENAS. Um ataque de força bruta
# que levaria minutos em MD5, levaria SÉCULOS em bcrypt.

def registrar(username, password):
    senha_bytes = password.encode()

    # gensalt() gera um salt aleatório + define o cost factor (padrão 12)
    salt = bcrypt.gensalt()

    # hashpw() combina senha + salt e aplica o algoritmo lento do bcrypt
    # O resultado inclui: versão do algoritmo + cost + salt + hash
    # Tudo numa string só, tipo: $2b$12$LJ3m4ys3Lg...
    senha_hash = bcrypt.hashpw(senha_bytes, salt)

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO usuarios (username, password, method)
    VALUES (?, ?, 'bcrypt')
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
        # checkpw() extrai o salt do próprio hash armazenado e recalcula.
        # Não precisa guardar o salt separadamente — essa é a beleza do bcrypt.
        return bcrypt.checkpw(
            password.encode(),
            senha_hash
        )

    return False
