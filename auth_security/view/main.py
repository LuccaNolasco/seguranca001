import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import sqlite3
import os
import sys
import gc
import hashlib
import time
import threading
import re

# ============================================================
# CONFIGURAÇÃO DE PATHS E IMPORTS
# ============================================================
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(parent_dir)
os.chdir(parent_dir)

# --- PATCH SQLITE PARA EVITAR "DATABASE IS LOCKED" ---
# Os módulos auth_*.py abrem conexões que às vezes ficam pendentes.
# Esse patch garante que a gente sempre consiga fechar tudo direitinho.
_original_connect = sqlite3.connect
_active_connections = []

def patched_connect(*args, **kwargs):
    kwargs.setdefault('timeout', 15)
    conn = _original_connect(*args, **kwargs)
    _active_connections.append(conn)
    return conn

sqlite3.connect = patched_connect

def limpar_conexoes():
    gc.collect()
    for c in _active_connections:
        try:
            c.close()
        except Exception:
            pass
    _active_connections.clear()

import database
database.criar_banco()
database.migrar_banco()
limpar_conexoes()

# Limpa o usuário "admin" que o auth_plain.py original criava no import
try:
    tmp_conn = _original_connect("users.db")
    tmp_conn.execute("DELETE FROM usuarios WHERE username='admin'")
    tmp_conn.commit()
    tmp_conn.close()
except Exception:
    pass

import auth_plain
import auth_md5
import auth_salt
import auth_bcrypt
limpar_conexoes()

# ============================================================
# TOP 100 SENHAS MAIS COMUNS (extraídas do RockYou — o famoso vazamento de 2009)
# Usamos essa lista pra simular ataques de dicionário.
# Na vida real, atacantes usam listas com BILHÕES de senhas.
# ============================================================
SENHAS_COMUNS = [
    "123456", "12345", "123456789", "password", "iloveyou",
    "princess", "1234567", "rockyou", "12345678", "abc123",
    "nicole", "daniel", "babygirl", "monkey", "lovely",
    "jessica", "654321", "michael", "ashley", "qwerty",
    "111111", "iloveu", "000000", "michelle", "tigger",
    "sunshine", "chocolate", "password1", "soccer", "anthony",
    "friends", "butterfly", "purple", "angel", "jordan",
    "liverpool", "justin", "loveme", "fuckyou", "123123",
    "football", "secret", "andrea", "carlos", "jennifer",
    "joshua", "bubbles", "1234567890", "superman", "hannah",
    "amanda", "loveyou", "pretty", "basketball", "andrew",
    "angels", "tweety", "flower", "playboy", "hello",
    "elizabeth", "hottie", "tinkerbell", "charlie", "samantha",
    "barbie", "chelsea", "lovers", "teamo", "jasmine",
    "brandon", "666666", "shadow", "melissa", "eminem",
    "matthew", "robert", "danielle", "forever", "family",
    "jonathan", "987654321", "computer", "whatever", "dragon",
    "vanessa", "cookie", "naruto", "summer", "sweety",
    "spongebob", "joseph", "junior", "sophia", "kevin",
    "nicolas", "master", "admin", "senhaforte", "teste123",
]

# ============================================================
# CORES E ESTILOS — pra facilitar a visualização dos níveis de segurança
# ============================================================
COR_PERIGO = "#e74c3c"       # Vermelho — inseguro
COR_ALERTA = "#e67e22"       # Laranja — frágil
COR_ATENCAO = "#f39c12"      # Amarelo — melhorou mas não é ideal
COR_SEGURO = "#27ae60"       # Verde — recomendado
COR_BG = "#2c3e50"           # Fundo escuro
COR_BG_CLARO = "#34495e"     # Fundo um pouco mais claro
COR_TEXTO = "#ecf0f1"        # Texto claro
COR_DESTAQUE = "#3498db"     # Azul destaque

METODO_COR = {
    "plain": COR_PERIGO,
    "md5": COR_ALERTA,
    "salt": COR_ATENCAO,
    "bcrypt": COR_SEGURO,
}

METODO_NOME = {
    "plain": "Texto Puro",
    "md5": "MD5",
    "salt": "SHA-256 + Salt",
    "bcrypt": "Bcrypt",
}

METODO_NIVEL = {
    "plain": "CRÍTICO",
    "md5": "FRACO",
    "salt": "MODERADO",
    "bcrypt": "FORTE",
}


class AppGUI(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("🛡 Sistema de Autenticação — Análise de Segurança")
        self.geometry("1050x700")
        self.minsize(950, 650)
        self.configure(bg=COR_BG)

        # Estilo ttk customizado para visual mais moderno
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self._configurar_estilos()

        # Notebook principal (abas)
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(expand=True, fill="both", padx=5, pady=5)

        # Criando cada aba
        self.aba_cadastro = ttk.Frame(self.notebook)
        self.aba_banco = ttk.Frame(self.notebook)
        self.aba_ataque = ttk.Frame(self.notebook)
        self.aba_comparacao = ttk.Frame(self.notebook)
        self.aba_melhorias = ttk.Frame(self.notebook)

        self.notebook.add(self.aba_cadastro, text="  📝 Cadastro / Login  ")
        self.notebook.add(self.aba_banco, text="  🗄 Banco de Dados (Vazamento)  ")
        self.notebook.add(self.aba_ataque, text="  ⚔ Simulação de Ataque  ")
        self.notebook.add(self.aba_comparacao, text="  📊 Comparação de Métodos  ")
        self.notebook.add(self.aba_melhorias, text="  🔐 Melhorias de Segurança  ")

        self.setup_aba_cadastro()
        self.setup_aba_banco()
        self.setup_aba_ataque()
        self.setup_aba_comparacao()
        self.setup_aba_melhorias()

        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_change)

        # Controle de tentativas de login (melhoria de segurança)
        self.tentativas_login = {}

    def _configurar_estilos(self):
        s = self.style
        s.configure("TNotebook", background=COR_BG)
        s.configure("TNotebook.Tab", background=COR_BG_CLARO, foreground=COR_TEXTO,
                     padding=[12, 6], font=("Segoe UI", 10))
        s.map("TNotebook.Tab", background=[("selected", COR_DESTAQUE)])

        s.configure("TFrame", background=COR_BG)
        s.configure("TLabel", background=COR_BG, foreground=COR_TEXTO, font=("Segoe UI", 10))
        s.configure("TButton", font=("Segoe UI", 10, "bold"), padding=6)
        s.configure("TRadiobutton", background=COR_BG, foreground=COR_TEXTO, font=("Segoe UI", 10))
        s.configure("Header.TLabel", font=("Segoe UI", 14, "bold"), foreground=COR_DESTAQUE, background=COR_BG)
        s.configure("Subtitle.TLabel", font=("Segoe UI", 11), foreground="#bdc3c7", background=COR_BG)

        s.configure("Danger.TLabel", foreground=COR_PERIGO, background=COR_BG, font=("Segoe UI", 10, "bold"))
        s.configure("Warning.TLabel", foreground=COR_ALERTA, background=COR_BG, font=("Segoe UI", 10, "bold"))
        s.configure("Caution.TLabel", foreground=COR_ATENCAO, background=COR_BG, font=("Segoe UI", 10, "bold"))
        s.configure("Safe.TLabel", foreground=COR_SEGURO, background=COR_BG, font=("Segoe UI", 10, "bold"))

        # Barra de força: em Tk 8.6 + tema "clam", um estilo novo precisa HERDAR o layout do
        # TProgressbar; senão o Tcl procura "Horizontal.Strength.TProgressbar" e estoura com
        # TclError: Layout ... not found (comum no Linux/WSL).
        for layout_name in ("TProgressbar", "Horizontal.TProgressbar"):
            try:
                s.layout("Strength.TProgressbar", s.layout(layout_name))
                break
            except tk.TclError:
                continue
        s.configure("Strength.TProgressbar", troughcolor=COR_BG_CLARO, background=COR_PERIGO)

    # ============================================================
    # ABA 1: CADASTRO E LOGIN
    # ============================================================
    def setup_aba_cadastro(self):
        frame = ttk.Frame(self.aba_cadastro, padding=20)
        frame.pack(expand=True, fill="both")

        ttk.Label(frame, text="Cadastro e Login de Usuários", style="Header.TLabel").pack(pady=(0, 5))
        ttk.Label(frame, text="Teste cada método de segurança e observe a diferença no banco de dados",
                  style="Subtitle.TLabel").pack(pady=(0, 20))

        # Container central
        center = ttk.Frame(frame)
        center.pack()

        # Método de segurança
        ttk.Label(center, text="Método de Segurança:").grid(row=0, column=0, sticky="nw", pady=5, padx=(0, 15))
        self.metodo_var = tk.StringVar(value="plain")

        frame_radios = ttk.Frame(center)
        frame_radios.grid(row=0, column=1, sticky="w", pady=5)

        metodos = [
            ("🔴 Texto Puro (Plain Text)", "plain"),
            ("🟠 Hash MD5", "md5"),
            ("🟡 Hash SHA-256 + Salt", "salt"),
            ("🟢 Bcrypt (Recomendado)", "bcrypt"),
        ]
        for text, value in metodos:
            ttk.Radiobutton(frame_radios, text=text, value=value, variable=self.metodo_var).pack(anchor="w", pady=1)

        # Usuário
        ttk.Label(center, text="Usuário:").grid(row=1, column=0, sticky="w", pady=8, padx=(0, 15))
        self.entry_user = ttk.Entry(center, width=35, font=("Segoe UI", 11))
        self.entry_user.grid(row=1, column=1, pady=8)

        # Senha
        ttk.Label(center, text="Senha:").grid(row=2, column=0, sticky="w", pady=8, padx=(0, 15))
        self.entry_senha = ttk.Entry(center, width=35, show="*", font=("Segoe UI", 11))
        self.entry_senha.grid(row=2, column=1, pady=8)
        self.entry_senha.bind("<KeyRelease>", self.atualizar_forca_senha)

        # Indicador de força da senha
        ttk.Label(center, text="Força da senha:").grid(row=3, column=0, sticky="w", pady=5, padx=(0, 15))
        frame_forca = ttk.Frame(center)
        frame_forca.grid(row=3, column=1, sticky="w", pady=5)

        self.barra_forca = ttk.Progressbar(frame_forca, length=250, mode="determinate",
                                           style="Strength.TProgressbar")
        self.barra_forca.pack(side="left")
        self.label_forca = ttk.Label(frame_forca, text="  —", width=15)
        self.label_forca.pack(side="left", padx=5)

        # Checkbox para habilitar proteção por tentativas
        self.protecao_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(center, text="🔒 Habilitar bloqueio por tentativas (melhoria)",
                        variable=self.protecao_var).grid(row=4, column=0, columnspan=2, pady=10)

        # Checkbox para validação de senha forte
        self.validacao_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(center, text="🔑 Exigir senha forte no cadastro (melhoria)",
                        variable=self.validacao_var).grid(row=5, column=0, columnspan=2, pady=2)

        # Botões
        frame_botoes = ttk.Frame(center)
        frame_botoes.grid(row=6, column=0, columnspan=2, pady=20)

        ttk.Button(frame_botoes, text="📋 Registrar", command=self.registrar).pack(side="left", padx=10)
        ttk.Button(frame_botoes, text="🔓 Login", command=self.login).pack(side="left", padx=10)
        ttk.Button(frame_botoes, text="🗑 Limpar Banco", command=self.limpar_banco).pack(side="left", padx=10)

        # Label de status
        self.label_status = ttk.Label(center, text="", style="Subtitle.TLabel")
        self.label_status.grid(row=7, column=0, columnspan=2, pady=5)

    def calcular_forca_senha(self, senha):
        """Retorna um score de 0-100 e uma descrição da força da senha."""
        if not senha:
            return 0, "—", COR_PERIGO

        score = 0
        if len(senha) >= 8:
            score += 25
        if len(senha) >= 12:
            score += 10
        if re.search(r'[A-Z]', senha):
            score += 20
        if re.search(r'[a-z]', senha):
            score += 10
        if re.search(r'[0-9]', senha):
            score += 15
        if re.search(r'[^A-Za-z0-9]', senha):
            score += 20

        # Penalidade se a senha está na lista de comuns
        if senha.lower() in [s.lower() for s in SENHAS_COMUNS]:
            score = min(score, 10)

        if score < 25:
            return score, "Muito fraca", COR_PERIGO
        elif score < 50:
            return score, "Fraca", COR_ALERTA
        elif score < 75:
            return score, "Razoável", COR_ATENCAO
        else:
            return score, "Forte", COR_SEGURO

    def atualizar_forca_senha(self, event=None):
        senha = self.entry_senha.get()
        score, desc, cor = self.calcular_forca_senha(senha)
        self.barra_forca["value"] = score
        self.label_forca.configure(text=f"  {desc}", foreground=cor)
        self.style.configure("Strength.TProgressbar", background=cor)

    def validar_senha_forte(self, senha):
        """Valida se a senha atende aos critérios de política de senha forte."""
        erros = []
        if len(senha) < 8:
            erros.append("• Mínimo de 8 caracteres")
        if not re.search(r'[A-Z]', senha):
            erros.append("• Pelo menos 1 letra maiúscula")
        if not re.search(r'[a-z]', senha):
            erros.append("• Pelo menos 1 letra minúscula")
        if not re.search(r'[0-9]', senha):
            erros.append("• Pelo menos 1 número")
        if not re.search(r'[^A-Za-z0-9]', senha):
            erros.append("• Pelo menos 1 caractere especial (!@#$%...)")
        if senha.lower() in [s.lower() for s in SENHAS_COMUNS]:
            erros.append("• A senha está na lista de senhas comuns (rockyou.txt)")
        return erros

    # ============================================================
    # ABA 2: BANCO DE DADOS — SIMULAÇÃO DE VAZAMENTO
    # ============================================================
    def setup_aba_banco(self):
        frame = ttk.Frame(self.aba_banco, padding=15)
        frame.pack(expand=True, fill="both")

        ttk.Label(frame, text="Banco de Dados — Visão do Atacante",
                  style="Header.TLabel").pack(pady=(0, 5))
        ttk.Label(frame,
                  text="É isso que um atacante vê quando o banco de dados é vazado. "
                       "Note a diferença entre cada método.",
                  style="Subtitle.TLabel").pack(pady=(0, 15))

        # Frame de legenda
        legenda = ttk.Frame(frame)
        legenda.pack(fill="x", pady=(0, 10))
        ttk.Label(legenda, text="Legenda: ", font=("Segoe UI", 10, "bold")).pack(side="left")
        for metodo, cor in METODO_COR.items():
            lbl = tk.Label(legenda, text=f" ● {METODO_NOME[metodo]} ", bg=COR_BG, fg=cor,
                           font=("Segoe UI", 9, "bold"))
            lbl.pack(side="left", padx=5)

        # Treeview
        colunas = ("ID", "Usuário", "Senha/Hash Armazenado", "Salt", "Método", "Nível")
        self.tree = ttk.Treeview(frame, columns=colunas, show="headings", height=15)

        larguras = {"ID": 40, "Usuário": 100, "Senha/Hash Armazenado": 420, "Salt": 180, "Método": 100, "Nível": 80}
        for col in colunas:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=larguras.get(col, 100), minwidth=40)

        self.tree.tag_configure("plain", foreground=COR_PERIGO)
        self.tree.tag_configure("md5", foreground=COR_ALERTA)
        self.tree.tag_configure("salt", foreground=COR_ATENCAO)
        self.tree.tag_configure("bcrypt", foreground=COR_SEGURO)

        self.tree.pack(expand=True, fill="both", side="left")

        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

        # Botões
        frame_btn = ttk.Frame(self.aba_banco)
        frame_btn.pack(pady=8)
        ttk.Button(frame_btn, text="🔄 Atualizar", command=self.carregar_dados_banco).pack(side="left", padx=5)
        ttk.Button(frame_btn, text="📋 Cadastrar Usuários de Teste",
                   command=self.cadastrar_usuarios_teste).pack(side="left", padx=5)

    # ============================================================
    # ABA 3: SIMULAÇÃO DE ATAQUE
    # ============================================================
    def setup_aba_ataque(self):
        frame = ttk.Frame(self.aba_ataque, padding=15)
        frame.pack(expand=True, fill="both")

        ttk.Label(frame, text="Simulação de Ataque — Banco Vazado",
                  style="Header.TLabel").pack(pady=(0, 5))
        ttk.Label(frame,
                  text="Simula o que acontece quando um atacante obtém acesso ao banco de dados "
                       "e tenta descobrir as senhas usando um dicionário de senhas comuns (estilo rockyou.txt).",
                  style="Subtitle.TLabel").pack(pady=(0, 10))

        # Opções do ataque
        opcoes = ttk.Frame(frame)
        opcoes.pack(fill="x", pady=5)

        ttk.Label(opcoes, text="Atacar método:").pack(side="left", padx=5)
        self.ataque_metodo = tk.StringVar(value="todos")
        for txt, val in [("Todos", "todos"), ("Plain", "plain"), ("MD5", "md5"),
                         ("SHA-256+Salt", "salt"), ("Bcrypt", "bcrypt")]:
            ttk.Radiobutton(opcoes, text=txt, value=val, variable=self.ataque_metodo).pack(side="left", padx=5)

        ttk.Button(opcoes, text="⚔ INICIAR ATAQUE", command=self.iniciar_ataque).pack(side="right", padx=10)

        # Área de output do ataque
        self.texto_ataque = scrolledtext.ScrolledText(frame, wrap=tk.WORD, font=("Consolas", 10),
                                                      bg="#1a1a2e", fg="#00ff41",
                                                      insertbackground="#00ff41", height=20)
        self.texto_ataque.pack(expand=True, fill="both", pady=10)

        # Tags de cor para o output
        self.texto_ataque.tag_configure("header", foreground="#00d4ff", font=("Consolas", 11, "bold"))
        self.texto_ataque.tag_configure("found", foreground="#ff4444", font=("Consolas", 10, "bold"))
        self.texto_ataque.tag_configure("safe", foreground="#00ff41", font=("Consolas", 10, "bold"))
        self.texto_ataque.tag_configure("info", foreground="#ffaa00")
        self.texto_ataque.tag_configure("time", foreground="#aa88ff")
        self.texto_ataque.tag_configure("separator", foreground="#555577")

        # Resumo do ataque
        self.frame_resumo_ataque = ttk.Frame(frame)
        self.frame_resumo_ataque.pack(fill="x", pady=5)

    # ============================================================
    # ABA 4: COMPARAÇÃO DE MÉTODOS
    # ============================================================
    def setup_aba_comparacao(self):
        frame = ttk.Frame(self.aba_comparacao, padding=15)
        frame.pack(expand=True, fill="both")

        ttk.Label(frame, text="Comparação de Métodos de Segurança",
                  style="Header.TLabel").pack(pady=(0, 5))
        ttk.Label(frame,
                  text="Veja lado a lado como cada método se comporta em diferentes aspectos de segurança.",
                  style="Subtitle.TLabel").pack(pady=(0, 15))

        ttk.Button(frame, text="🔬 Executar Benchmark", command=self.executar_benchmark).pack(pady=5)

        # Container para os cards
        self.frame_cards = ttk.Frame(frame)
        self.frame_cards.pack(expand=True, fill="both", pady=10)

        # Texto de benchmark
        self.texto_benchmark = scrolledtext.ScrolledText(frame, wrap=tk.WORD, font=("Consolas", 10),
                                                         bg="#1a1a2e", fg="#e0e0e0", height=10)
        self.texto_benchmark.pack(fill="both", expand=True, pady=5)
        self.texto_benchmark.tag_configure("header", foreground="#00d4ff", font=("Consolas", 11, "bold"))
        self.texto_benchmark.tag_configure("result", foreground="#ffaa00")
        self.texto_benchmark.tag_configure("safe", foreground="#00ff41", font=("Consolas", 10, "bold"))
        self.texto_benchmark.tag_configure("danger", foreground="#ff4444", font=("Consolas", 10, "bold"))

        self._criar_cards_comparacao()

    def _criar_cards_comparacao(self):
        """Cria os 4 cards de comparação — um pra cada método."""
        dados = [
            ("plain", "🔴 Texto Puro", COR_PERIGO, [
                "Armazena: senha em texto",
                "Tempo p/ quebrar: INSTANTÂNEO",
                "Rainbow table: N/A (já é texto)",
                "Salt: Não usa",
                "Se vazar: GAME OVER total",
            ]),
            ("md5", "🟠 Hash MD5", COR_ALERTA, [
                "Armazena: hash de 32 chars",
                "Tempo p/ quebrar: SEGUNDOS",
                "Rainbow table: VULNERÁVEL",
                "Salt: Não usa",
                "Se vazar: Descoberta rápida",
            ]),
            ("salt", "🟡 SHA-256 + Salt", COR_ATENCAO, [
                "Armazena: hash 64 chars + salt",
                "Tempo p/ quebrar: HORAS/DIAS",
                "Rainbow table: IMUNE",
                "Salt: Sim, único por usuário",
                "Se vazar: Precisa força bruta",
            ]),
            ("bcrypt", "🟢 Bcrypt", COR_SEGURO, [
                "Armazena: hash com salt embutido",
                "Tempo p/ quebrar: ANOS/SÉCULOS",
                "Rainbow table: IMUNE",
                "Salt: Automático + cost factor",
                "Se vazar: Praticamente seguro",
            ]),
        ]

        for i, (metodo, titulo, cor, infos) in enumerate(dados):
            card = tk.Frame(self.frame_cards, bg=COR_BG_CLARO, highlightbackground=cor,
                            highlightthickness=2, padx=12, pady=10)
            card.grid(row=0, column=i, padx=6, pady=5, sticky="nsew")
            self.frame_cards.columnconfigure(i, weight=1)

            tk.Label(card, text=titulo, bg=COR_BG_CLARO, fg=cor,
                     font=("Segoe UI", 11, "bold")).pack(anchor="w")
            tk.Label(card, text=f"Nível: {METODO_NIVEL[metodo]}", bg=COR_BG_CLARO, fg=cor,
                     font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 8))

            for info in infos:
                tk.Label(card, text=info, bg=COR_BG_CLARO, fg=COR_TEXTO,
                         font=("Segoe UI", 9), anchor="w", justify="left").pack(anchor="w", pady=1)

    # ============================================================
    # ABA 5: MELHORIAS DE SEGURANÇA
    # ============================================================
    def setup_aba_melhorias(self):
        frame = ttk.Frame(self.aba_melhorias, padding=15)
        frame.pack(expand=True, fill="both")

        ttk.Label(frame, text="Melhorias Implementadas", style="Header.TLabel").pack(pady=(0, 5))
        ttk.Label(frame,
                  text="Funcionalidades de segurança adicionais que vão além do armazenamento de hash.",
                  style="Subtitle.TLabel").pack(pady=(0, 15))

        # ScrolledText com as melhorias
        texto = scrolledtext.ScrolledText(frame, wrap=tk.WORD, font=("Segoe UI", 11),
                                          bg=COR_BG_CLARO, fg=COR_TEXTO, height=25)
        texto.pack(expand=True, fill="both")

        texto.tag_configure("titulo", foreground=COR_DESTAQUE, font=("Segoe UI", 13, "bold"))
        texto.tag_configure("subtitulo", foreground=COR_SEGURO, font=("Segoe UI", 11, "bold"))
        texto.tag_configure("codigo", foreground="#e6db74", font=("Consolas", 10), background="#1a1a2e")
        texto.tag_configure("alerta", foreground=COR_PERIGO, font=("Segoe UI", 10, "bold"))
        texto.tag_configure("destaque", foreground=COR_ATENCAO, font=("Segoe UI", 10, "bold"))

        conteudo = [
            ("titulo", "🔐 MELHORIA 1: Bloqueio por Tentativas de Login\n\n"),
            ("normal", "Quando habilitado (checkbox na aba de Cadastro/Login), o sistema bloqueia "
                       "o login após 3 tentativas falhas consecutivas por 30 segundos.\n\n"),
            ("subtitulo", "Por que isso importa?\n"),
            ("normal", "Sem esse controle, um atacante pode testar milhares de senhas por segundo "
                       "diretamente no sistema (ataque de força bruta online). Com o bloqueio, "
                       "ele fica limitado a ~6 tentativas por minuto — levaria SÉCULOS pra testar "
                       "um dicionário inteiro.\n\n"),
            ("subtitulo", "Como funciona:\n"),
            ("codigo", "  Se tentativas > 3:\n"
                       "      bloquear por 30 segundos\n"
                       "      mostrar tempo restante ao usuário\n"
                       "  Se login OK:\n"
                       "      zerar contador de tentativas\n\n"),

            ("titulo", "🔑 MELHORIA 2: Política de Senha Forte\n\n"),
            ("normal", "Quando habilitado, o sistema rejeita senhas que não atendam aos critérios:\n\n"),
            ("destaque", "  ✓ Mínimo de 8 caracteres\n"
                         "  ✓ Pelo menos 1 letra maiúscula (A-Z)\n"
                         "  ✓ Pelo menos 1 letra minúscula (a-z)\n"
                         "  ✓ Pelo menos 1 número (0-9)\n"
                         "  ✓ Pelo menos 1 caractere especial (!@#$%...)\n"
                         "  ✓ Não pode estar na lista de senhas comuns\n\n"),
            ("subtitulo", "Por que isso importa?\n"),
            ("normal", "A maioria dos vazamentos bem-sucedidos acontece porque os usuários "
                       "escolhem senhas como '123456' ou 'password'. Forçar complexidade mínima "
                       "aumenta drasticamente o espaço de busca que um atacante precisa cobrir.\n\n"),

            ("titulo", "📊 MELHORIA 3: Indicador Visual de Força da Senha\n\n"),
            ("normal", "A barra de progresso na aba de cadastro mostra em tempo real a força "
                       "da senha digitada, considerando comprimento, variedade de caracteres "
                       "e presença em listas de senhas comuns.\n\n"),

            ("titulo", "⚔ MELHORIA 4: Simulação de Ataque com Dicionário\n\n"),
            ("normal", "A aba de Simulação de Ataque demonstra o que acontece quando um banco "
                       "de dados é vazado. Ela executa ataques reais de dicionário contra "
                       "os hashes armazenados, usando as 100 senhas mais comuns do RockYou.\n\n"),
            ("alerta", "  O contraste é gritante:\n"),
            ("normal", "  • Plain Text → senha visível sem nenhum esforço\n"
                       "  • MD5 → quebrado em milissegundos\n"
                       "  • SHA-256 + Salt → cada tentativa precisa usar o salt do usuário\n"
                       "  • Bcrypt → cada tentativa leva ~100ms, tornando dicionários inviáveis\n\n"),

            ("titulo", "🔒 MELHORIA 5: Migração Segura do Banco de Dados\n\n"),
            ("normal", "O sistema detecta automaticamente se o banco de dados está na versão "
                       "antiga (sem as colunas 'method', 'login_attempts', 'locked_until') "
                       "e faz a migração sem perder dados existentes.\n\n"),

            ("titulo", "📈 MELHORIA 6: Benchmark Comparativo\n\n"),
            ("normal", "Na aba de Comparação, o benchmark mede o tempo real de hash para cada "
                       "método, mostrando numericamente por que bcrypt é mais seguro: "
                       "ele é centenas de vezes mais lento que MD5 POR DESIGN.\n"),
        ]

        for tag, txt in conteudo:
            if tag == "normal":
                texto.insert(tk.END, txt)
            else:
                texto.insert(tk.END, txt, tag)

        texto.configure(state="disabled")

    # ============================================================
    # LÓGICA: CADASTRO E LOGIN
    # ============================================================
    def get_modulo_auth(self):
        metodo = self.metodo_var.get()
        if metodo == "plain":  return auth_plain
        if metodo == "md5":    return auth_md5
        if metodo == "salt":   return auth_salt
        if metodo == "bcrypt": return auth_bcrypt
        return None

    def registrar(self):
        limpar_conexoes()
        usuario = self.entry_user.get().strip()
        senha = self.entry_senha.get()

        if not usuario or not senha:
            messagebox.showwarning("Aviso", "Preencha usuário e senha.")
            return

        # Melhoria: validação de senha forte (quando habilitada)
        if self.validacao_var.get():
            erros = self.validar_senha_forte(senha)
            if erros:
                msg = "A senha não atende à política de segurança:\n\n" + "\n".join(erros)
                messagebox.showerror("Senha Fraca", msg)
                return

        modulo = self.get_modulo_auth()
        try:
            modulo.registrar(usuario, senha)
            metodo = self.metodo_var.get()
            messagebox.showinfo("Sucesso",
                f"Usuário '{usuario}' registrado com {METODO_NOME[metodo]}!\n\n"
                f"Vá na aba 'Banco de Dados' para ver como a senha foi armazenada.")
            self.entry_user.delete(0, tk.END)
            self.entry_senha.delete(0, tk.END)
            self.atualizar_forca_senha()
        except sqlite3.IntegrityError:
            messagebox.showerror("Erro", "Nome de usuário já existe!")
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao registrar:\n{e}")
        finally:
            limpar_conexoes()

    def login(self):
        limpar_conexoes()
        usuario = self.entry_user.get().strip()
        senha = self.entry_senha.get()

        if not usuario or not senha:
            messagebox.showwarning("Aviso", "Preencha usuário e senha.")
            return

        # Melhoria: bloqueio por tentativas (quando habilitado)
        if self.protecao_var.get():
            agora = time.time()
            info = self.tentativas_login.get(usuario, {"count": 0, "locked_until": 0})

            if agora < info["locked_until"]:
                restante = int(info["locked_until"] - agora)
                messagebox.showerror("🔒 Conta Bloqueada",
                    f"Muitas tentativas falhas!\n\n"
                    f"Aguarde {restante} segundos para tentar novamente.\n\n"
                    f"(Essa é a melhoria de bloqueio por tentativas em ação)")
                return

        modulo = self.get_modulo_auth()
        try:
            sucesso = modulo.login(usuario, senha)
            if sucesso:
                if self.protecao_var.get():
                    self.tentativas_login[usuario] = {"count": 0, "locked_until": 0}
                messagebox.showinfo("Login", "✅ Login efetuado com SUCESSO!")
            else:
                if self.protecao_var.get():
                    info = self.tentativas_login.get(usuario, {"count": 0, "locked_until": 0})
                    info["count"] += 1
                    if info["count"] >= 3:
                        info["locked_until"] = time.time() + 30
                        info["count"] = 0
                        self.tentativas_login[usuario] = info
                        messagebox.showerror("🔒 Conta Bloqueada",
                            f"3 tentativas falhas! Conta bloqueada por 30 segundos.\n\n"
                            f"(Sem essa proteção, um atacante poderia testar milhares de senhas)")
                        return
                    self.tentativas_login[usuario] = info
                    restantes = 3 - info["count"]
                    messagebox.showerror("Login Falhou",
                        f"Usuário ou senha inválidos!\n\nTentativas restantes: {restantes}")
                else:
                    messagebox.showerror("Login", "Usuário ou senha inválidos!")
        except Exception as e:
            messagebox.showerror("Erro", f"Erro no login:\n{e}")
        finally:
            limpar_conexoes()

    # ============================================================
    # LÓGICA: BANCO DE DADOS (VAZAMENTO)
    # ============================================================
    def carregar_dados_banco(self):
        limpar_conexoes()
        for item in self.tree.get_children():
            self.tree.delete(item)

        try:
            conn = _original_connect("users.db")
            cursor = conn.cursor()

            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='usuarios'")
            if cursor.fetchone() is None:
                database.criar_banco()

            cursor.execute("SELECT id, username, password, salt, method FROM usuarios")
            registros = cursor.fetchall()

            for reg in registros:
                id_, user, pwd, salt, method = reg
                if method is None:
                    method = "plain"
                # Decodifica bytes do bcrypt se necessário
                if isinstance(pwd, bytes):
                    pwd = pwd.decode('utf-8', errors='replace')
                nivel = METODO_NIVEL.get(method, "?")
                self.tree.insert("", "end", values=(id_, user, pwd, salt or "—", METODO_NOME.get(method, method), nivel),
                                 tags=(method,))

            conn.close()
        except sqlite3.Error as e:
            messagebox.showerror("Erro", f"Não foi possível carregar os dados:\n{e}")
        finally:
            limpar_conexoes()

    def cadastrar_usuarios_teste(self):
        """Cadastra um usuário de teste com CADA método, usando a mesma senha,
        para que o professor veja como a mesma senha é armazenada de formas diferentes."""
        limpar_conexoes()
        senha_teste = "123456"
        resultados = []

        for modulo, metodo_nome in [(auth_plain, "Plain"), (auth_md5, "MD5"),
                                     (auth_salt, "SHA256+Salt"), (auth_bcrypt, "Bcrypt")]:
            username = f"teste_{metodo_nome.lower().replace('+', '_')}"
            try:
                modulo.registrar(username, senha_teste)
                resultados.append(f"✅ {username} → registrado com {metodo_nome}")
            except sqlite3.IntegrityError:
                resultados.append(f"⚠ {username} → já existe")
            except Exception as e:
                resultados.append(f"❌ {username} → erro: {e}")
            finally:
                limpar_conexoes()

        messagebox.showinfo("Usuários de Teste",
            f"Todos usam a senha '{senha_teste}' — veja como ela fica armazenada:\n\n" +
            "\n".join(resultados) +
            "\n\nAgora vá na aba 'Banco de Dados' para ver a diferença!")
        self.carregar_dados_banco()

    def limpar_banco(self):
        """Remove todos os registros para começar do zero."""
        if not messagebox.askyesno("Confirmar", "Isso vai apagar TODOS os usuários. Continuar?"):
            return
        limpar_conexoes()
        try:
            conn = _original_connect("users.db")
            conn.execute("DELETE FROM usuarios")
            conn.commit()
            conn.close()
            messagebox.showinfo("Limpo", "Banco de dados limpo!")
            self.carregar_dados_banco()
        except Exception as e:
            messagebox.showerror("Erro", str(e))
        finally:
            limpar_conexoes()

    # ============================================================
    # LÓGICA: SIMULAÇÃO DE ATAQUE
    # ============================================================
    def iniciar_ataque(self):
        """Executa a simulação de ataque em uma thread separada para não travar a GUI."""
        self.texto_ataque.configure(state="normal")
        self.texto_ataque.delete("1.0", tk.END)
        self.texto_ataque.insert(tk.END, "⏳ Iniciando simulação de ataque...\n\n", "header")
        self.texto_ataque.configure(state="disabled")

        thread = threading.Thread(target=self._executar_ataque, daemon=True)
        thread.start()

    def _log_ataque(self, texto, tag="normal"):
        """Escreve no console de ataque de forma thread-safe."""
        def _insert():
            self.texto_ataque.configure(state="normal")
            self.texto_ataque.insert(tk.END, texto, tag if tag != "normal" else ())
            self.texto_ataque.see(tk.END)
            self.texto_ataque.configure(state="disabled")
        self.after(0, _insert)

    def _executar_ataque(self):
        """Coração da simulação: tenta quebrar cada senha do banco usando dicionário."""
        try:
            conn = _original_connect("users.db")
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, password, salt, method FROM usuarios")
            registros = cursor.fetchall()
            conn.close()
        except Exception as e:
            self._log_ataque(f"Erro ao ler banco: {e}\n", "found")
            return

        if not registros:
            self._log_ataque("⚠ Banco de dados vazio! Cadastre usuários primeiro.\n", "info")
            self._log_ataque("  Dica: Use o botão 'Cadastrar Usuários de Teste' na aba de Banco de Dados.\n", "info")
            return

        filtro = self.ataque_metodo.get()
        resultados = {"plain": [], "md5": [], "salt": [], "bcrypt": []}
        total_inicio = time.time()

        self._log_ataque("=" * 70 + "\n", "separator")
        self._log_ataque("  SIMULAÇÃO DE VAZAMENTO DE BANCO DE DADOS\n", "header")
        self._log_ataque("  Cenário: O atacante obteve uma cópia completa do banco de dados\n", "info")
        self._log_ataque(f"  Dicionário: {len(SENHAS_COMUNS)} senhas comuns (top do RockYou)\n", "info")
        self._log_ataque(f"  Registros no banco: {len(registros)}\n", "info")
        self._log_ataque("=" * 70 + "\n\n", "separator")

        for id_, username, pwd_hash, salt, method in registros:
            if method is None:
                method = "plain"
            if filtro != "todos" and method != filtro:
                continue

            if isinstance(pwd_hash, bytes):
                pwd_hash = pwd_hash.decode('utf-8', errors='replace')

            self._log_ataque(f"─── Atacando usuário: {username} (método: {METODO_NOME.get(method, method)}) ───\n", "header")
            self._log_ataque(f"  Hash armazenado: {pwd_hash[:60]}{'...' if len(pwd_hash) > 60 else ''}\n", "info")
            if salt:
                self._log_ataque(f"  Salt: {salt}\n", "info")

            inicio = time.time()
            senha_encontrada = None
            tentativas = 0

            if method == "plain":
                # Plain text: a senha está ali, aberta, sem fazer nada
                self._log_ataque("\n  [!] A senha está em TEXTO PURO — nem precisa atacar!\n", "found")
                self._log_ataque(f"  >>> SENHA: {pwd_hash} <<<\n", "found")
                tempo = 0.0
                senha_encontrada = pwd_hash
                tentativas = 0

            elif method == "md5":
                # MD5: tenta cada senha do dicionário, calculando o hash e comparando
                self._log_ataque("\n  Executando ataque de dicionário contra MD5...\n")
                for senha_teste in SENHAS_COMUNS:
                    tentativas += 1
                    hash_teste = hashlib.md5(senha_teste.encode()).hexdigest()
                    if hash_teste == pwd_hash:
                        senha_encontrada = senha_teste
                        break
                tempo = time.time() - inicio

                if senha_encontrada:
                    self._log_ataque(f"  >>> SENHA DESCOBERTA: {senha_encontrada} (em {tentativas} tentativas) <<<\n", "found")
                else:
                    self._log_ataque(f"  Senha NÃO encontrada no dicionário ({tentativas} tentativas)\n", "safe")
                    self._log_ataque(f"  (Mas um dicionário maior ou rainbow table quebraria facilmente)\n", "info")

            elif method == "salt":
                # SHA-256 + Salt: precisa recalcular com o salt de cada usuário
                self._log_ataque("\n  Executando ataque de dicionário contra SHA-256+Salt...\n")
                self._log_ataque("  (Rainbow tables NÃO funcionam aqui — cada salt é único)\n", "info")
                for senha_teste in SENHAS_COMUNS:
                    tentativas += 1
                    hash_teste = hashlib.sha256((senha_teste + (salt or "")).encode()).hexdigest()
                    if hash_teste == pwd_hash:
                        senha_encontrada = senha_teste
                        break
                tempo = time.time() - inicio

                if senha_encontrada:
                    self._log_ataque(f"  >>> SENHA DESCOBERTA: {senha_encontrada} (em {tentativas} tentativas) <<<\n", "found")
                    self._log_ataque(f"  (O salt protege contra rainbow tables, mas senhas fracas ainda caem em dicionário)\n", "info")
                else:
                    self._log_ataque(f"  Senha NÃO encontrada no dicionário ({tentativas} tentativas)\n", "safe")

            elif method == "bcrypt":
                # Bcrypt: cada tentativa é DELIBERADAMENTE lenta
                self._log_ataque("\n  Executando ataque de dicionário contra Bcrypt...\n")
                self._log_ataque("  (Perceba como cada tentativa demora — esse é o ponto do bcrypt!)\n", "info")

                pwd_bytes = pwd_hash.encode('utf-8') if isinstance(pwd_hash, str) else pwd_hash

                max_tentativas_bcrypt = min(20, len(SENHAS_COMUNS))
                self._log_ataque(f"  (Limitando a {max_tentativas_bcrypt} tentativas porque bcrypt é LENTO de propósito)\n", "info")

                for i, senha_teste in enumerate(SENHAS_COMUNS[:max_tentativas_bcrypt]):
                    tentativas += 1
                    try:
                        if bcrypt_check_safe(senha_teste, pwd_bytes):
                            senha_encontrada = senha_teste
                            break
                    except Exception:
                        pass

                    if i % 5 == 4:
                        elapsed = time.time() - inicio
                        self._log_ataque(f"  ... {tentativas} tentativas em {elapsed:.2f}s "
                                         f"(~{tentativas/elapsed:.1f} tentativas/seg)\n", "time")

                tempo = time.time() - inicio

                if senha_encontrada:
                    self._log_ataque(f"  >>> SENHA DESCOBERTA: {senha_encontrada} (em {tentativas} tentativas, {tempo:.2f}s) <<<\n", "found")
                    self._log_ataque(f"  (Mesmo encontrando, note o TEMPO — com dicionário grande, levaria ANOS)\n", "info")
                else:
                    self._log_ataque(f"  Senha NÃO encontrada ({tentativas} tentativas em {tempo:.2f}s)\n", "safe")
                    self._log_ataque(f"  (E isso foram só {max_tentativas_bcrypt} senhas! Imagine testar bilhões...)\n", "safe")

            self._log_ataque(f"\n  ⏱ Tempo do ataque: {tempo:.4f}s | Tentativas: {tentativas}\n", "time")

            if method == "bcrypt" and tentativas > 0 and tempo > 0:
                taxa = tentativas / tempo
                tempo_100 = len(SENHAS_COMUNS) / taxa
                self._log_ataque(f"  📊 Taxa: {taxa:.1f} tentativas/seg\n", "time")
                self._log_ataque(f"  📊 Tempo estimado p/ testar as {len(SENHAS_COMUNS)} senhas: {tempo_100:.1f}s\n", "time")
            elif method == "md5" and tentativas > 0 and tempo > 0:
                taxa = tentativas / tempo
                self._log_ataque(f"  📊 Taxa: {taxa:.0f} tentativas/seg (RÁPIDO DEMAIS!)\n", "time")
            elif method == "salt" and tentativas > 0 and tempo > 0:
                taxa = tentativas / tempo
                self._log_ataque(f"  📊 Taxa: {taxa:.0f} tentativas/seg\n", "time")

            self._log_ataque("\n", "separator")

            resultados[method].append({
                "user": username, "encontrada": senha_encontrada is not None,
                "senha": senha_encontrada, "tempo": tempo, "tentativas": tentativas
            })

        # Resumo final
        total_tempo = time.time() - total_inicio
        self._log_ataque("\n" + "=" * 70 + "\n", "separator")
        self._log_ataque("  📋 RESUMO DO ATAQUE\n", "header")
        self._log_ataque("=" * 70 + "\n\n", "separator")

        for method in ["plain", "md5", "salt", "bcrypt"]:
            if not resultados[method]:
                continue
            quebradas = sum(1 for r in resultados[method] if r["encontrada"])
            total = len(resultados[method])
            self._log_ataque(f"  {METODO_NOME.get(method, method):20s} → ", "info")
            if quebradas == total:
                self._log_ataque(f"{quebradas}/{total} senhas descobertas ❌ INSEGURO\n", "found")
            elif quebradas > 0:
                self._log_ataque(f"{quebradas}/{total} senhas descobertas ⚠ PARCIAL\n", "info")
            else:
                self._log_ataque(f"0/{total} senhas resistiram ✅ SEGURO\n", "safe")

        self._log_ataque(f"\n  Tempo total da simulação: {total_tempo:.2f}s\n", "time")
        self._log_ataque("\n  CONCLUSÃO: A diferença de segurança é GRITANTE.\n", "header")
        self._log_ataque("  Plain Text e MD5 são inaceitáveis para qualquer sistema real.\n", "info")
        self._log_ataque("  Bcrypt é o padrão recomendado — lento POR DESIGN.\n\n", "safe")

    # ============================================================
    # LÓGICA: BENCHMARK DE COMPARAÇÃO
    # ============================================================
    def executar_benchmark(self):
        """Benchmark usando os dados REAIS do banco: tenta quebrar cada usuário
        com o dicionário de senhas comuns e mede o tempo por método."""
        self.texto_benchmark.configure(state="normal")
        self.texto_benchmark.delete("1.0", tk.END)

        # Lê os usuários reais do banco
        limpar_conexoes()
        try:
            conn = _original_connect("users.db")
            cursor = conn.cursor()
            cursor.execute("SELECT username, password, salt, method FROM usuarios")
            registros = cursor.fetchall()
            conn.close()
        except Exception as e:
            self.texto_benchmark.insert(tk.END, f"Erro ao ler banco: {e}\n", "danger")
            self.texto_benchmark.configure(state="disabled")
            return

        if not registros:
            self.texto_benchmark.insert(tk.END, "⚠ Banco de dados vazio!\n\n", "danger")
            self.texto_benchmark.insert(tk.END,
                "Cadastre usuários primeiro (aba Cadastro/Login) ou use o botão\n"
                "'Cadastrar Usuários de Teste' na aba Banco de Dados.\n", "result")
            self.texto_benchmark.configure(state="disabled")
            return

        # Agrupa por método
        por_metodo = {}
        for username, pwd_hash, salt, method in registros:
            method = method or "plain"
            if isinstance(pwd_hash, bytes):
                pwd_hash = pwd_hash.decode("utf-8", errors="replace")
            por_metodo.setdefault(method, []).append((username, pwd_hash, salt))

        self.texto_benchmark.insert(tk.END, "🔬 BENCHMARK: Quebra real contra o banco de dados\n", "header")
        self.texto_benchmark.insert(tk.END,
            f"Usuários no banco: {len(registros)}  |  "
            f"Dicionário: {len(SENHAS_COMUNS)} senhas (top RockYou)\n\n")
        self.update()

        tempos_metodo = {}
        resultados_metodo = {}

        for metodo in ["plain", "md5", "salt", "bcrypt"]:
            usuarios = por_metodo.get(metodo, [])
            if not usuarios:
                continue

            self.texto_benchmark.insert(tk.END,
                f"── {METODO_NOME[metodo]} ({len(usuarios)} usuário(s)) ──\n", "header")
            self.update()

            quebradas = 0
            inicio_metodo = time.time()

            for username, pwd_hash, salt in usuarios:
                encontrada = None
                inicio = time.time()

                if metodo == "plain":
                    if pwd_hash in SENHAS_COMUNS:
                        encontrada = pwd_hash
                    tempo_usr = time.time() - inicio

                elif metodo == "md5":
                    for s in SENHAS_COMUNS:
                        if hashlib.md5(s.encode()).hexdigest() == pwd_hash:
                            encontrada = s
                            break
                    tempo_usr = time.time() - inicio

                elif metodo == "salt":
                    for s in SENHAS_COMUNS:
                        if hashlib.sha256((s + (salt or "")).encode()).hexdigest() == pwd_hash:
                            encontrada = s
                            break
                    tempo_usr = time.time() - inicio

                elif metodo == "bcrypt":
                    pwd_bytes = pwd_hash.encode("utf-8") if isinstance(pwd_hash, str) else pwd_hash
                    max_t = min(20, len(SENHAS_COMUNS))
                    for s in SENHAS_COMUNS[:max_t]:
                        try:
                            if bcrypt_check_safe(s, pwd_bytes):
                                encontrada = s
                                break
                        except Exception:
                            pass
                    tempo_usr = time.time() - inicio

                tag = "danger" if encontrada else "safe"
                status = f"QUEBRADA → {encontrada}" if encontrada else "RESISTIU"
                self.texto_benchmark.insert(tk.END,
                    f"  {username:20s}  {status:30s}  {tempo_usr:.4f}s\n", tag)
                self.update()

                if encontrada:
                    quebradas += 1

            tempo_total = time.time() - inicio_metodo
            tempos_metodo[metodo] = tempo_total
            resultados_metodo[metodo] = (quebradas, len(usuarios))

            self.texto_benchmark.insert(tk.END,
                f"  Resultado: {quebradas}/{len(usuarios)} quebradas em {tempo_total:.4f}s\n\n", "result")

        # --- Resumo comparativo ---
        self.texto_benchmark.insert(tk.END, "═" * 65 + "\n", "header")
        self.texto_benchmark.insert(tk.END, "📊 RESUMO COMPARATIVO\n", "header")
        self.texto_benchmark.insert(tk.END, "═" * 65 + "\n\n", "header")

        self.texto_benchmark.insert(tk.END,
            f"{'Método':<22} {'Quebradas':<14} {'Tempo':<12} {'Veredicto'}\n")
        self.texto_benchmark.insert(tk.END, "─" * 65 + "\n")

        for metodo in ["plain", "md5", "salt", "bcrypt"]:
            if metodo not in resultados_metodo:
                continue
            quebradas, total = resultados_metodo[metodo]
            tempo = tempos_metodo[metodo]

            if quebradas == total:
                veredicto = "❌ INSEGURO"
                tag = "danger"
            elif quebradas > 0:
                veredicto = "⚠ PARCIAL"
                tag = "result"
            else:
                veredicto = "✅ SEGURO"
                tag = "safe"

            self.texto_benchmark.insert(tk.END,
                f"  {METODO_NOME[metodo]:<20} {quebradas}/{total:<11} {tempo:.4f}s     {veredicto}\n", tag)

        # Estimativa de tempo para dicionário grande
        self.texto_benchmark.insert(tk.END, "\n")
        self.texto_benchmark.insert(tk.END, "📊 ESTIMATIVA: Tempo para testar 1 BILHÃO de senhas\n", "header")
        self.texto_benchmark.insert(tk.END, "─" * 65 + "\n")

        for metodo in ["md5", "salt", "bcrypt"]:
            if metodo not in tempos_metodo or metodo not in resultados_metodo:
                continue
            _, total_usr = resultados_metodo[metodo]
            if total_usr == 0:
                continue

            tempo_por_usr = tempos_metodo[metodo] / total_usr
            n_senhas = len(SENHAS_COMUNS) if metodo != "bcrypt" else min(20, len(SENHAS_COMUNS))
            tempo_por_tentativa = tempo_por_usr / n_senhas if n_senhas > 0 else 0
            tempo_1bi = tempo_por_tentativa * 1_000_000_000

            if tempo_1bi < 60:
                tempo_str = f"{tempo_1bi:.1f} segundos"
            elif tempo_1bi < 3600:
                tempo_str = f"{tempo_1bi/60:.1f} minutos"
            elif tempo_1bi < 86400:
                tempo_str = f"{tempo_1bi/3600:.1f} horas"
            elif tempo_1bi < 86400 * 365:
                tempo_str = f"{tempo_1bi/86400:.1f} dias"
            else:
                tempo_str = f"{tempo_1bi/(86400*365):.0f} anos"

            tag = "danger" if metodo == "md5" else ("result" if metodo == "salt" else "safe")
            self.texto_benchmark.insert(tk.END,
                f"  {METODO_NOME[metodo]:<20} → {tempo_str}\n", tag)

        if tempos_metodo.get("md5") and tempos_metodo.get("bcrypt"):
            razao = tempos_metodo["bcrypt"] / tempos_metodo["md5"] if tempos_metodo["md5"] > 0 else 0
            self.texto_benchmark.insert(tk.END,
                f"\n⚡ Bcrypt levou ~{int(razao)}x mais tempo que MD5 para o mesmo ataque!\n", "safe")

        self.texto_benchmark.insert(tk.END,
            "\nIsso é PROPOSITAL — quanto mais lento, mais seguro contra força bruta.\n", "result")
        self.texto_benchmark.insert(tk.END,
            "(GPUs aceleram MD5/SHA enormemente, mas NÃO bcrypt)\n\n", "result")

        # Explicação didática do que os números significam
        self.texto_benchmark.insert(tk.END, "═" * 65 + "\n", "header")
        self.texto_benchmark.insert(tk.END, "💡 COMO INTERPRETAR ESSES RESULTADOS\n", "header")
        self.texto_benchmark.insert(tk.END, "═" * 65 + "\n\n", "header")

        self.texto_benchmark.insert(tk.END,
            "\"Se foi tão rápido, por que a estimativa fala em horas/dias?\"\n\n", "safe")
        self.texto_benchmark.insert(tk.END,
            "O ataque acima testou apenas 100 senhas comuns contra poucos\n"
            "usuários — por isso terminou em menos de 1 segundo.\n\n")
        self.texto_benchmark.insert(tk.END,
            "Mas senhas como '123456' são as PRIMEIRAS que um atacante testa.\n"
            "Se a senha for forte (ex: 'K#8mPx!qZ2$n'), ela NÃO estará em\n"
            "nenhum dicionário. O atacante terá que testar TODAS as combinações\n"
            "possíveis (força bruta), e aí o número de tentativas explode:\n\n", "result")
        self.texto_benchmark.insert(tk.END,
            "  • 8 chars minúsculos:           ~209 bilhões de combinações\n"
            "  • 8 chars com maiúsc+números:    ~218 trilhões\n"
            "  • 12 chars com tudo + especiais: ~475 quatrilhões\n\n")
        self.texto_benchmark.insert(tk.END,
            "A estimativa pega o tempo REAL medido por tentativa neste PC\n"
            "e extrapola: \"a esta velocidade, quanto demoraria pra testar\n"
            "1 bilhão de senhas?\" — e a diferença fica gritante:\n\n", "result")
        self.texto_benchmark.insert(tk.END,
            "  MD5      →  cada tentativa leva nanosegundos  → horas\n", "danger")
        self.texto_benchmark.insert(tk.END,
            "  Bcrypt   →  cada tentativa leva ~100ms        → MESES/ANOS\n\n", "safe")
        self.texto_benchmark.insert(tk.END,
            "CONCLUSÃO: Bcrypt não impede que '123456' seja descoberta\n"
            "(porque é a 1ª senha de qualquer dicionário). Mas torna\n"
            "IMPRATICÁVEL testar todas as combinações de uma senha forte.\n"
            "A segurança real = bcrypt + senha forte + bloqueio de tentativas.\n", "safe")

        self.texto_benchmark.configure(state="disabled")

    # ============================================================
    # EVENTOS
    # ============================================================
    def on_tab_change(self, event):
        idx = self.notebook.index("current")
        if idx == 1:
            self.carregar_dados_banco()


def bcrypt_check_safe(senha_teste, pwd_bytes):
    """Wrapper para bcrypt.checkpw que lida com encoding."""
    import bcrypt as _bcrypt
    return _bcrypt.checkpw(senha_teste.encode(), pwd_bytes)


if __name__ == "__main__":
    app = AppGUI()
    app.mainloop()
