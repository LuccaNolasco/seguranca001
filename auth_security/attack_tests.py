import hashlib
import time

# ============================================================
# TESTE DE ATAQUE: Dicionário contra hash MD5
# ============================================================
# Isso simula o que um atacante faz quando obtém um hash MD5 de um banco vazado.
# Ele pega uma lista de senhas comuns e calcula o MD5 de cada uma,
# comparando com o hash que ele tem. Se bater, ele descobriu a senha.
# Com MD5, isso leva MILISSEGUNDOS — é assustadoramente rápido.

senhas_comuns = [
    "123456", "password", "admin", "qwerty", "12345678",
    "abc123", "monkey", "master", "dragon", "111111",
    "letmein", "trustno1", "iloveyou", "sunshine", "princess",
]

# Esse é o hash MD5 de "password" — uma das senhas mais usadas no mundo
hash_alvo = "5f4dcc3b5aa765d61d8327deb882cf99"

print("=" * 50)
print("ATAQUE DE DICIONÁRIO CONTRA HASH MD5")
print(f"Hash alvo: {hash_alvo}")
print(f"Dicionário: {len(senhas_comuns)} senhas")
print("=" * 50)

inicio = time.time()
encontrada = False

for i, senha in enumerate(senhas_comuns, 1):
    hash_teste = hashlib.md5(senha.encode()).hexdigest()
    print(f"  Tentativa {i:3d}: {senha:15s} → {hash_teste}")

    if hash_teste == hash_alvo:
        tempo = time.time() - inicio
        print(f"\n>>> SENHA DESCOBERTA: '{senha}' em {tempo:.4f}s ({i} tentativas) <<<")
        encontrada = True
        break

if not encontrada:
    tempo = time.time() - inicio
    print(f"\nSenha não encontrada ({tempo:.4f}s, {len(senhas_comuns)} tentativas)")

print(f"\nConclusão: MD5 é INSEGURO para armazenamento de senhas.")
print(f"Um atacante com GPU testa bilhões de hashes MD5 por segundo.")
