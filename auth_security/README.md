# Segurança de Senhas - Trabalho 01

Este diretório contém códigos que demonstram a evolução das abordagens de segurança para armazenamento de senhas em um sistema:

- `auth_plain.py`: Senha em texto puro (plain text).
- `auth_md5.py`: Senha armazenada com hash MD5.
- `auth_salt.py`: Senha armazenada com hash SHA-256 + Salt.
- `auth_bcrypt.py`: Senha armazenada com hash bcrypt.

## Interface Gráfica (GUI)

Foi adicionada uma interface gráfica no diretório `view/` para facilitar os testes de cada método de segurança e a visualização do banco de dados.

Para iniciar a interface, execute:
```bash
python view/main.py
```
Nela, você poderá:
- Selecionar o método de segurança que deseja usar (Plain, MD5, Salt ou Bcrypt).
- Realizar o registro ou login de usuários.
- Visualizar todos os registros do banco de dados na aba "Banco de Dados".

## Dependências e Instalação

Para rodar os exemplos acima, é necessário instalar as dependências do projeto. A única biblioteca externa utilizada é a `bcrypt` (além das bibliotecas nativas do Python, como `sqlite3`, `hashlib` e `os`).

### Como instalar as dependências

Você pode instalar as dependências rodando os scripts de instalação fornecidos:

- **No Windows:**
  Dê um duplo clique no arquivo `install_deps.bat` ou execute-o no terminal:
  ```cmd
  .\install_deps.bat
  ```

- **No Linux / macOS:**
  Dê permissão de execução e rode o script `.sh`:
  ```bash
  chmod +x install_deps.sh
  ./install_deps.sh
  ```

Alternativamente, você pode instalar manualmente utilizando o `pip`:
```bash
pip install -r requirements.txt
```

Após a instalação, todos os arquivos `.py` poderão ser executados sem problemas de dependência.
