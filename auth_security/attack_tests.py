import hashlib

# Lista de senhas comuns

senhas_comuns = [
    "123456",
    "password",
    "admin",
    "qwerty"
]

hash_alvo = "5f4dcc3b5aa765d61d8327deb882cf99"

for senha in senhas_comuns:

    if hashlib.md5(senha.encode()).hexdigest() == hash_alvo:

        print("Senha descoberta:", senha)
