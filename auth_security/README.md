# 🛡 Segurança em Sistema de Autenticação — Trabalho Prático

Sistema de autenticação que demonstra a evolução das abordagens de segurança para armazenamento de senhas, com interface gráfica para visualização e simulação de ataques.

## 📁 Estrutura do Projeto

```
auth_security/
├── database.py          # Criação e migração do banco SQLite
├── auth_plain.py        # Cenário A: Senha em texto puro (INSEGURO)
├── auth_md5.py          # Cenário B: Hash MD5 (FRÁGIL)
├── auth_salt.py         # Cenário C: SHA-256 + Salt (MODERADO)
├── auth_bcrypt.py       # Cenário D: Bcrypt (RECOMENDADO)
├── attack_tests.py      # Teste de ataque de dicionário contra MD5
├── requirements.txt     # Dependências (bcrypt)
├── install_deps.bat     # Instalador Windows
├── install_deps.sh      # Instalador Linux/Mac
├── view/
│   └── main.py          # Interface gráfica completa
└── users.db             # Banco de dados SQLite (gerado na execução)
```

## 🚀 Como Executar

### Linux sem venv (pacotes do sistema)

Assim você não usa `venv` nem `pip` no Python global: instale **bcrypt** e **tkinter** pelo apt e rode com `python3` do sistema.

```bash
sudo apt update
sudo apt install python3-bcrypt python3-tk
cd auth_security
python3 view/main.py
```

Confira se o módulo carrega: `python3 -c "import bcrypt; import tkinter; print('OK')"`

Se o seu Ubuntu não tiver `python3-bcrypt` no repositório, aí sim use **uma** destas opções (menos ideal):

```bash
# opção A — usuário atual, sem mexer no sistema (pode falhar com PEP 668)
python3 -m pip install --user bcrypt

# opção B — força instalação no Python do sistema (use por sua conta e risco)
python3 -m pip install bcrypt --break-system-packages
```

### Linux / macOS (recomendado: ambiente virtual)

No Ubuntu/Debian, `pip install` no Python do sistema costuma falhar com **externally-managed-environment** (PEP 668). Use um **venv**:

```bash
cd auth_security
chmod +x install_deps.sh run.sh
./install_deps.sh
./run.sh
```

Ou manualmente:

```bash
cd auth_security
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 view/main.py
```

Para sair do ambiente virtual: `deactivate`

### Windows (PowerShell)

```powershell
cd auth_security
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python view\main.py
```

### Tkinter no Linux

Se aparecer `No module named 'tkinter'`:

```bash
sudo apt install python3-tk python3-venv
```

## 🖥 Funcionalidades da Interface

### 📝 Aba 1: Cadastro / Login
- Cadastro e login com cada método de segurança
- Indicador visual de força da senha em tempo real
- Toggle para habilitar bloqueio por tentativas (melhoria)
- Toggle para exigir senha forte no cadastro (melhoria)

### 🗄 Aba 2: Banco de Dados (Vazamento)
- Visualização do banco como um atacante veria após um vazamento
- Color-coded por nível de segurança (vermelho→verde)
- Botão para cadastrar usuários de teste com todos os métodos

### ⚔ Aba 3: Simulação de Ataque
- Ataque de dicionário real contra os hashes armazenados
- Usa as 100 senhas mais comuns do RockYou
- Mostra tempo, tentativas e taxa por método
- Demonstra visualmente a diferença brutal entre os métodos

### 📊 Aba 4: Comparação de Métodos
- Cards comparativos lado a lado
- Benchmark real medindo tempo de hash
- Estimativa de tempo para ataques em larga escala

### 🔐 Aba 5: Melhorias de Segurança
- Documentação das 6 melhorias implementadas
- Explicação de cada funcionalidade adicionada

## 🔒 Melhorias Implementadas

1. **Bloqueio por tentativas** — Bloqueia login após 3 falhas por 30s
2. **Política de senha forte** — Exige complexidade mínima no cadastro
3. **Indicador de força** — Feedback visual em tempo real
4. **Simulação de ataque** — Demonstra vulnerabilidades de forma prática
5. **Migração de banco** — Adiciona colunas novas sem perder dados
6. **Benchmark comparativo** — Mede performance real de cada algoritmo

## 📚 Dependências

- Python 3.8+
- `bcrypt` (instalado via pip)
- `tkinter` (incluído no Python padrão)
- `sqlite3` (incluído no Python padrão)
