import sqlite3
from werkzeug.security import generate_password_hash
from datetime import datetime

conn = sqlite3.connect('banco.db')

# Criação das tabelas
conn.execute('''
CREATE TABLE IF NOT EXISTS usuarios (
    matricula TEXT PRIMARY KEY,
    nome TEXT NOT NULL,
    senha TEXT NOT NULL,
    perfil TEXT NOT NULL,
    data_cadastro TEXT,
    usuario_responsavel TEXT,
    data_acao TEXT,
    hora_acao TEXT,
    usuario_acao TEXT
)
''')

conn.execute('''
CREATE TABLE IF NOT EXISTS redefinicoes_senha (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    matricula TEXT,
    data_requisicao TEXT,
    hora_requisicao TEXT
)
''')

conn.execute('''
CREATE TABLE IF NOT EXISTS maquinas (
    id_maquina TEXT PRIMARY KEY,
    nome_maquina TEXT NOT NULL,
    setor TEXT NOT NULL,
    meta_hora INTEGER,
    meta_dia INTEGER,
    data_cadastro TEXT,
    usuario_responsavel TEXT,
    data_acao TEXT,
    hora_acao TEXT,
    usuario_acao TEXT
)
''')

# Inserção de um usuário administrador padrão (opcional)
try:
    conn.execute('''
        INSERT INTO usuarios (matricula, nome, senha, perfil, data_cadastro, usuario_responsavel)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        '002971',
        'Rafael Santiago',
        generate_password_hash('rafael072025'),
        'Administrador',
        datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'sistema'
    ))
    print("Usuário administrador criado com sucesso.")
except sqlite3.IntegrityError:
    print("Usuário administrador já existe.")

conn.commit()
conn.close()
