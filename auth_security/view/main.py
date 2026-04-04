import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import os
import sys
import gc

# Adiciona o diretório pai ao path para importar os módulos de autenticação
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(parent_dir)

# Muda o diretório de trabalho para que o users.db seja salvo/lido no local correto
os.chdir(parent_dir)

# --- PATCH SQLITE PARA EVITAR DATABASE IS LOCKED ---
# Essa abordagem resolve o problema de conexões que ficam pendentes (vazadas)
# pelos arquivos de autenticação (como auth_salt.py ou após um IntegrityError)
# respeitando a regra de NÃO alterar os arquivos originais.
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
# ---------------------------------------------------

import database
# Configurar o banco de dados ANTES de importar os outros módulos
database.criar_banco()
limpar_conexoes()

# O auth_plain.py possui um teste solto que registra o usuário "admin".
# Para evitar o IntegrityError no import na segunda execução, apagamos o admin previamente.
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

class AppGUI(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Sistema de Autenticação Segura")
        self.geometry("600x400")

        # Criar as abas
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(expand=True, fill="both")

        self.aba_cadastro = ttk.Frame(self.notebook)
        self.aba_banco = ttk.Frame(self.notebook)

        self.notebook.add(self.aba_cadastro, text="Cadastro/Login")
        self.notebook.add(self.aba_banco, text="Banco de Dados")

        self.setup_aba_cadastro()
        self.setup_aba_banco()

        # Atualizar os dados do banco ao mudar de aba
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_change)

    def setup_aba_cadastro(self):
        # Frame principal para centralizar
        frame = ttk.Frame(self.aba_cadastro, padding=20)
        frame.pack(expand=True)

        # Seleção de Método
        ttk.Label(frame, text="Método de Segurança:").grid(row=0, column=0, sticky="w", pady=5)
        self.metodo_var = tk.StringVar(value="plain")
        
        metodos = [
            ("Texto Puro (Plain)", "plain"),
            ("Hash MD5", "md5"),
            ("Hash SHA-256 + Salt", "salt"),
            ("Hash Bcrypt", "bcrypt")
        ]
        
        frame_radios = ttk.Frame(frame)
        frame_radios.grid(row=0, column=1, sticky="w", pady=5)
        for text, value in metodos:
            ttk.Radiobutton(frame_radios, text=text, value=value, variable=self.metodo_var).pack(anchor="w")

        # Usuário
        ttk.Label(frame, text="Usuário:").grid(row=1, column=0, sticky="w", pady=5)
        self.entry_user = ttk.Entry(frame, width=30)
        self.entry_user.grid(row=1, column=1, pady=5)

        # Senha
        ttk.Label(frame, text="Senha:").grid(row=2, column=0, sticky="w", pady=5)
        self.entry_senha = ttk.Entry(frame, width=30, show="*")
        self.entry_senha.grid(row=2, column=1, pady=5)

        # Botões
        frame_botoes = ttk.Frame(frame)
        frame_botoes.grid(row=3, column=0, columnspan=2, pady=20)

        ttk.Button(frame_botoes, text="Registrar", command=self.registrar).pack(side="left", padx=10)
        ttk.Button(frame_botoes, text="Login", command=self.login).pack(side="left", padx=10)

    def setup_aba_banco(self):
        frame = ttk.Frame(self.aba_banco, padding=10)
        frame.pack(expand=True, fill="both")

        # Treeview para mostrar os dados
        colunas = ("ID", "Usuário", "Senha (Hash)", "Salt")
        self.tree = ttk.Treeview(frame, columns=colunas, show="headings")

        for col in colunas:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=120)

        self.tree.pack(expand=True, fill="both", side="left")

        # Scrollbar
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        
        # Botão de atualizar
        ttk.Button(self.aba_banco, text="Atualizar Dados", command=self.carregar_dados_banco).pack(pady=10)

    def on_tab_change(self, event):
        # Se a aba selecionada for a aba do banco de dados, atualiza os dados
        if self.notebook.index("current") == 1:
            self.carregar_dados_banco()

    def carregar_dados_banco(self):
        limpar_conexoes()
        # Limpar dados atuais
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Buscar dados do banco
        try:
            db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "users.db")
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Verificar se a tabela existe
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='usuarios'")
            if cursor.fetchone() is None:
                database.criar_banco()
                
            cursor.execute("SELECT id, username, password, salt FROM usuarios")
            registros = cursor.fetchall()
            
            for registro in registros:
                self.tree.insert("", "end", values=registro)
                
            conn.close()
        except sqlite3.Error as e:
            messagebox.showerror("Erro de Banco de Dados", f"Não foi possível carregar os dados:\n{e}")
        finally:
            limpar_conexoes()

    def get_modulo_auth(self):
        metodo = self.metodo_var.get()
        if metodo == "plain": return auth_plain
        if metodo == "md5": return auth_md5
        if metodo == "salt": return auth_salt
        if metodo == "bcrypt": return auth_bcrypt
        return None

    def registrar(self):
        limpar_conexoes()
        usuario = self.entry_user.get()
        senha = self.entry_senha.get()

        if not usuario or not senha:
            messagebox.showwarning("Aviso", "Por favor, preencha usuário e senha.")
            return

        modulo = self.get_modulo_auth()
        try:
            modulo.registrar(usuario, senha)
            messagebox.showinfo("Sucesso", "Usuário registrado com sucesso!")
            self.entry_user.delete(0, tk.END)
            self.entry_senha.delete(0, tk.END)
        except sqlite3.IntegrityError:
            messagebox.showerror("Erro", "Nome de usuário já existe!")
        except Exception as e:
            messagebox.showerror("Erro", f"Ocorreu um erro ao registrar:\n{e}")
        finally:
            limpar_conexoes()

    def login(self):
        limpar_conexoes()
        usuario = self.entry_user.get()
        senha = self.entry_senha.get()

        if not usuario or not senha:
            messagebox.showwarning("Aviso", "Por favor, preencha usuário e senha.")
            return

        modulo = self.get_modulo_auth()
        try:
            sucesso = modulo.login(usuario, senha)
            if sucesso:
                messagebox.showinfo("Login", "Login efetuado com SUCESSO!")
            else:
                messagebox.showerror("Login", "Usuário ou senha inválidos!")
        except Exception as e:
            messagebox.showerror("Erro", f"Ocorreu um erro no login:\n{e}")
        finally:
            limpar_conexoes()

if __name__ == "__main__":
    app = AppGUI()
    app.mainloop()
