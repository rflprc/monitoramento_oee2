from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import sqlite3
import contextlib
from functools import wraps

app = Flask(__name__)
app.secret_key = 'chave-secreta-segura'

# Configuração de timeout de sessão (30 minutos)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Decorator para verificar permissões de administrador
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('perfil_usuario') != 'Administrador':
            flash('Acesso não autorizado', 'erro')
            return redirect(url_for('pagina_inicial'))
        return f(*args, **kwargs)
    return decorated_function

# Gerenciamento seguro de conexões com o banco
@contextlib.contextmanager
def get_db_connection():
    conn = sqlite3.connect('banco.db')
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def atividade_ativa_maquina(id_maquina):
    with get_db_connection() as conn:
        atividade = conn.execute('''
            SELECT * FROM atividades
            WHERE id_maquina = ? AND data_fim IS NULL AND hora_fim IS NULL
            ORDER BY id_atividade DESC LIMIT 1
        ''', (id_maquina,)).fetchone()

    if atividade:
        return True, atividade
    return False, None

# Conexão com banco de dados
def get_db_connection():
    conn = sqlite3.connect('banco.db')
    conn.row_factory = sqlite3.Row
    return conn

def atividade_ativa_maquina(id_maquina):
    conn = get_db_connection()
    atividade = conn.execute('''
        SELECT * FROM atividades
        WHERE id_maquina = ? AND data_fim IS NULL AND hora_fim IS NULL
        ORDER BY id_atividade DESC LIMIT 1
    ''', (id_maquina,)).fetchone()
    conn.close()

    if atividade:
        return True, atividade
    return False, None


# Login

@app.route('/', methods=['GET', 'POST'])
def login():
    erro = None
    if request.method == 'POST':
        matricula = request.form['matricula']
        senha = request.form['senha']

        conn = get_db_connection()
        usuario = conn.execute('SELECT * FROM usuarios WHERE matricula = ?', (matricula,)).fetchone()
        conn.close()

        if usuario and check_password_hash(usuario['senha'], senha):
            session['usuario_logado'] = usuario['matricula']
            session['perfil_usuario'] = usuario['perfil']
            session['ultimo_acesso'] = str(datetime.now())
            session['nome_usuario'] = usuario['nome']  # Armazena o nome do usuário na sessão
            return redirect(url_for('pagina_inicial'))  # Página Inicial a ser implementada
        else:
            erro = 'Matrícula ou senha inválidos.'

    return render_template('login.html', erro=erro)

# Redefinição de Senha

@app.route('/redefinir_senha', methods=['GET', 'POST'])
def redefinir_senha():
    mensagem = None
    if request.method == 'POST':
        matricula = request.form['matricula']
        nova_senha = request.form['nova_senha']
        confirmar_senha = request.form['confirmar_nova_senha']

        if nova_senha != confirmar_senha:
            mensagem = 'As senhas não coincidem.'
        else:
            conn = get_db_connection()
            usuario = conn.execute('SELECT * FROM usuarios WHERE matricula = ?', (matricula,)).fetchone()

            if usuario:
                # Atualiza senha (use hash)
                senha_hash = generate_password_hash(nova_senha)
                conn.execute('UPDATE usuarios SET senha = ? WHERE matricula = ?', (senha_hash, matricula))
                # Registra redefinição
                agora = datetime.now()
                conn.execute(
                    'INSERT INTO redefinicoes_senha (matricula, data_requisicao, hora_requisicao) VALUES (?, ?, ?)',
                    (matricula, agora.date().isoformat(), agora.time().strftime('%H:%M:%S'))
                )
                conn.commit()
                conn.close()
                flash('Senha redefinida com sucesso.')
                return redirect(url_for('login'))
            else:
                mensagem = 'Matrícula não encontrada.'
    return render_template('redefinir_senha.html', mensagem=mensagem)

# Usuários
# Cadastro de Usuários

@app.route('/cadastrar_usuario', methods=['GET', 'POST'])
def cadastrar_usuario():
    if session.get('perfil_usuario') != 'Administrador':
        return redirect(url_for('pagina_inicial'))

    mensagem = None
    conn = get_db_connection()

    if request.method == 'POST':
        matricula = request.form['matricula']
        nome = request.form['nome']
        senha_pura = request.form['senha']
        confirmar_senha = request.form['confirmar_senha']        
        perfil = request.form['perfil']
        data_cadastro = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        responsavel = session.get('usuario_logado')

        if senha_pura != confirmar_senha:
            mensagem = "As senhas não coincidem."
        else:
            senha_hash = generate_password_hash(senha_pura)
            try:
                conn.execute('''
                    INSERT INTO usuarios (matricula, nome, senha, perfil, data_cadastro, usuario_responsavel)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (matricula, nome, senha_hash, perfil, data_cadastro, responsavel))
                conn.commit()
                mensagem = "Usuário cadastrado com sucesso!"
            except sqlite3.IntegrityError:
                mensagem = "Matrícula já cadastrada."

    usuarios = conn.execute('SELECT matricula, nome, perfil FROM usuarios').fetchall()
    conn.close()
    return render_template('cadastro_usuarios.html', usuarios=usuarios, mensagem=mensagem)

# Exclusão de Usuários (com verificação de dependências)
@app.route('/excluir_usuario/<matricula>')
@admin_required
def excluir_usuario(matricula):
    if matricula == session.get('usuario_logado'):
        flash('Você não pode excluir a si mesmo.', 'erro')
        return redirect(url_for('cadastrar_usuario'))
    
    try:
        with get_db_connection() as conn:
            # Verificar dependências
            atividades = conn.execute('SELECT COUNT(*) AS count FROM atividades WHERE operador_inicio = ? OR operador_fim = ?', 
                                     (matricula, matricula)).fetchone()
            
            if atividades['count'] > 0:
                flash('Não é possível excluir usuário com histórico de atividades', 'erro')
                return redirect(url_for('cadastrar_usuario'))
            
            conn.execute('DELETE FROM usuarios WHERE matricula = ?', (matricula,))
            conn.commit()
        
        flash('Usuário excluído com sucesso.')
    except sqlite3.Error as e:
        flash(f'Erro ao excluir usuário: {str(e)}', 'erro')
    
    return redirect(url_for('cadastrar_usuario'))

# Edição de Usuários

@app.route('/editar_usuario/<matricula>', methods=['GET', 'POST'])
def editar_usuario(matricula):
    if session.get('perfil_usuario') != 'Administrador':
        return redirect(url_for('pagina_inicial'))

    conn = get_db_connection()
    usuario = conn.execute('SELECT * FROM usuarios WHERE matricula = ?', (matricula,)).fetchone()

    if not usuario:
        flash('Usuário não encontrado.')
        return redirect(url_for('cadastrar_usuario'))

    if request.method == 'POST':
        nome = request.form['nome']
        senha_nova = request.form['senha']
        perfil = request.form['perfil']
        data_acao = datetime.now().strftime('%Y-%m-%d')
        hora_acao = datetime.now().strftime('%H:%M:%S')
        responsavel = session.get('usuario_logado')

        if senha_nova:
            senha_hash = generate_password_hash(senha_nova)
            conn.execute('''
                UPDATE usuarios 
                SET nome = ?, senha = ?, perfil = ?, data_acao = ?, hora_acao = ?, usuario_acao = ?
                WHERE matricula = ?
            ''', (nome, senha_hash, perfil, data_acao, hora_acao, responsavel, matricula))
        else:
            conn.execute('''
                UPDATE usuarios 
                SET nome = ?, perfil = ?, data_acao = ?, hora_acao = ?, usuario_acao = ?
                WHERE matricula = ?
            ''', (nome, perfil, data_acao, hora_acao, responsavel, matricula))
 
        flash('Usuário atualizado com sucesso.')
        return redirect(url_for('cadastrar_usuario'))

    conn.close()
    return render_template('editar_usuario.html', usuario=usuario)

# Logout

@app.route('/logout')
def logout():
    session.clear()
    flash('Logout realizado com sucesso.')
    return redirect(url_for('login'))

# Página Inicial

@app.route('/pagina_inicial')
def pagina_inicial():
    if 'usuario_logado' not in session:
        return redirect(url_for('login'))
    perfil = session.get('perfil_usuario')
    usuario = session.get('nome_usuario')  # Passa o nome para o template
    return render_template('pagina_inicial.html', perfil=perfil, usuario=usuario)


@app.route('/boas_vindas')
def boas_vindas():
    nome_usuario = session.get('nome_usuario', 'Usuário')  # Pega o nome da sessão
    perfil = session.get('perfil_usuario', 'Perfil não definido')
    return f'''
        <div style="padding: 20px;">
            <h2>Bem-vindo, {nome_usuario}!</h2>
            <p>Seu perfil: <strong>{perfil}</strong></p>
            <p>Use o menu ao lado para navegar pelas funções do sistema.</p>
        </div>
    '''

# Menu: Setores e Submenu: Máquinas
@app.route('/dados_setores_maquinas')
def dados_setores_maquinas():
    conn = get_db_connection()
    setores_maquinas = conn.execute('''
        SELECT setor, id_maquina, nome_maquina
        FROM maquinas
        ORDER BY setor, nome_maquina
    ''').fetchall()
    conn.close()

    estrutura = {}
    for row in setores_maquinas:
        setor = row['setor']
        if setor not in estrutura:
            estrutura[setor] = []
        estrutura[setor].append({
            'id': row['id_maquina'],
            'nome': row['nome_maquina']
        })
    return jsonify(estrutura)  # Flask já serializa em JSON automático se for dict

# Painel da Máquina

@app.route('/painel_maquina/<id_maquina>')
def painel_maquina(id_maquina):
    # Verificar se usuário está logado
    if 'usuario_logado' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Obter dados da máquina
    maquina = conn.execute('SELECT * FROM maquinas WHERE id_maquina = ?', (id_maquina,)).fetchone()
    
    # Obter nome do operador
    usuario = conn.execute('SELECT nome FROM usuarios WHERE matricula = ?', (session['usuario_logado'],)).fetchone()
    nome_operador = usuario['nome'] if usuario else 'Operador Desconhecido'
    
    # Dados simulados (serão substituídos por dados reais posteriormente)
    estado_atual = "Em Produção"
    ciclos_realizados = 342
    tempo_atividade = "6h 45m"
    tempo_paradas = "1h 15m"
    tempo_medio_ciclos = "45 segundos"
    
    conn.close()
    
    return render_template('painel_maquina.html', 
                           maquina=maquina,
                           nome_operador=nome_operador,
                           estado_atual=estado_atual,
                           ciclos_realizados=ciclos_realizados,
                           tempo_atividade=tempo_atividade,
                           tempo_paradas=tempo_paradas,
                           tempo_medio_ciclos=tempo_medio_ciclos)

# Máquinas
# Cadastro de Máquinas

@app.route('/cadastrar_maquina', methods=['GET', 'POST'])
def cadastrar_maquina():
    if 'usuario_logado' not in session:
        return redirect(url_for('login'))
    if session.get('perfil_usuario') != 'Administrador':
        return redirect(url_for('pagina_inicial'))

    mensagem = None
    conn = get_db_connection()

    if request.method == 'POST':
        id_maquina = request.form.get('id_maquina', '').strip()
        nome_maquina = request.form.get('nome_maquina', '').strip()
        setor = request.form.get('setor', '').strip()
        tipo_maquina = request.form.get('tipo_maquina', '').strip()
        meta_hora = request.form.get('meta_hora', '').strip()
        meta_dia = request.form.get('meta_dia', '').strip()
        data_cadastro = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        responsavel = session.get('usuario_logado')

        # Validação dos campos obrigatórios
        if not all([id_maquina, nome_maquina, setor, tipo_maquina, meta_hora, meta_dia]):
            mensagem = 'Preencha todos os campos obrigatórios.'
        else:
            try:
                conn.execute('''
                    INSERT INTO maquinas (id_maquina, nome_maquina, setor, meta_hora, meta_dia, tipo_maquina, data_cadastro, usuario_responsavel)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (id_maquina, nome_maquina, setor, meta_hora, meta_dia, tipo_maquina, data_cadastro, responsavel))
                conn.commit()
                mensagem = 'Máquina cadastrada com sucesso!'
            except sqlite3.IntegrityError:
                mensagem = 'ID da máquina já cadastrada.'

    maquinas = conn.execute('SELECT * FROM maquinas ORDER BY setor, nome_maquina').fetchall()
    conn.close()
    return render_template('cadastro_maquinas.html', maquinas=maquinas, mensagem=mensagem)

# Editar Máquinas

@app.route('/editar_maquina/<id_maquina>', methods=['GET', 'POST'])
def editar_maquina(id_maquina):
    if session.get('perfil_usuario') != 'Administrador':
        return redirect(url_for('pagina_inicial'))

    conn = get_db_connection()

    if request.method == 'POST':
        nome = request.form['nome_maquina']
        setor = request.form['setor']
        meta_hora = request.form['meta_hora']
        meta_dia = request.form['meta_dia']
        tipo = request.form['tipo_maquina']
        data_acao = datetime.now().strftime('%Y-%m-%d')
        hora_acao = datetime.now().strftime('%H:%M:%S')
        usuario_acao = session.get('usuario_logado')

        conn.execute('''
            UPDATE maquinas SET
                nome_maquina = ?,
                setor = ?,
                meta_hora = ?,
                meta_dia = ?,
                tipo_maquina = ?,
                data_acao = ?,
                hora_acao = ?,
                usuario_acao = ?
            WHERE id_maquina = ?
        ''', (nome, setor, meta_hora, meta_dia, tipo, data_acao, hora_acao, usuario_acao, id_maquina))
        conn.commit()
        conn.close()

        flash('Máquina atualizada com sucesso!')
        return redirect(url_for('cadastrar_maquina'))

    maquina = conn.execute('SELECT * FROM maquinas WHERE id_maquina = ?', (id_maquina,)).fetchone()
    conn.close()

    if not maquina:
        flash('Máquina não encontrada.')
        return redirect(url_for('cadastrar_maquina'))

    return render_template('editar_maquina.html', maquina=maquina)


# Exclusão de Máquinas (com verificação de dependências)
@app.route('/excluir_maquina/<id_maquina>')
@admin_required
def excluir_maquina(id_maquina):
    try:
        with get_db_connection() as conn:
            # Verificar dependências
            atividades = conn.execute('SELECT COUNT(*) AS count FROM atividades WHERE id_maquina = ?', 
                                    (id_maquina,)).fetchone()
            paradas = conn.execute('SELECT COUNT(*) AS count FROM paradas WHERE id_maquina = ?', 
                                  (id_maquina,)).fetchone()
            
            if atividades['count'] > 0 or paradas['count'] > 0:
                flash('Não é possível excluir máquina com histórico de atividades/paradas', 'erro')
                return redirect(url_for('cadastrar_maquina'))
            
            conn.execute('DELETE FROM maquinas WHERE id_maquina = ?', (id_maquina,))
            conn.commit()
        
        flash('Máquina excluída com sucesso.')
    except sqlite3.Error as e:
        flash(f'Erro ao excluir máquina: {str(e)}', 'erro')
    
    return redirect(url_for('cadastrar_maquina'))

# Controle de Produção

@app.route('/controle_producao/<id_maquina>', methods=['POST'])
def controle_producao(id_maquina):
    if 'usuario_logado' not in session:
        return redirect(url_for('login'))  # Proteção de sessão

    conn = get_db_connection()

    # Verifica se já há uma atividade ativa para essa máquina
    atividade_ativa = conn.execute('''
        SELECT * FROM atividades
        WHERE id_maquina = ? AND data_fim IS NULL AND hora_fim IS NULL
    ''', (id_maquina,)).fetchone()

    agora = datetime.now()
    data = agora.date().isoformat()
    hora = agora.time().strftime('%H:%M:%S')
    operador = session.get('usuario_logado')

    if atividade_ativa:
        # ENCERRAR produção
        id_atividade = atividade_ativa['id_atividade']
        # Corrigido: usar data + hora para datetime completo
        data_inicio = atividade_ativa['data_inicio']
        hora_inicio = atividade_ativa['hora_inicio']
        dt_inicio = datetime.strptime(f"{data_inicio} {hora_inicio}", "%Y-%m-%d %H:%M:%S")
        tempo_total = (agora - dt_inicio).total_seconds()

        # Calcular tempo médio de ciclo, se houver
        ciclos = atividade_ativa['ciclos_realizados'] or 0  # Tratar None
        tempo_medio = tempo_total / ciclos if ciclos > 0 else None

        conn.execute('''
            UPDATE atividades
            SET data_fim = ?, hora_fim = ?, operador_fim = ?, tempo_total_atividade = ?, tempo_medio_ciclo = ?
            WHERE id_atividade = ?
        ''', (
            data, hora, operador,
            tempo_total,
            tempo_medio if tempo_medio else None,
            id_atividade
        ))

        mensagem = "Produção encerrada com sucesso."

    else:
        # INICIAR produção
        conn.execute('''
            INSERT INTO atividades (id_maquina, data_inicio, hora_inicio, operador_inicio)
            VALUES (?, ?, ?, ?)
        ''', (id_maquina, data, hora, operador))

        mensagem = "Produção iniciada com sucesso."

    conn.commit()
    conn.close()
    flash(mensagem)
    return redirect(url_for('pagina_controle_maquina', id_maquina=id_maquina))

@app.route('/controle_maquina/<id_maquina>')
def pagina_controle_maquina(id_maquina):
    ativo, atividade = atividade_ativa_maquina(id_maquina)

    conn = get_db_connection()
    historico = conn.execute('''
        SELECT * FROM atividades
        WHERE id_maquina = ?
        ORDER BY id_atividade DESC
        LIMIT 10
    ''', (id_maquina,)).fetchall()
    conn.close()

    return render_template(
        'controle_maquina.html',
        id_maquina=id_maquina,
        atividade_ativa=ativo,
        atividade=atividade,
        historico=historico
    )

# Ações da Produção

# Ação Produção

@app.route('/acao_producao/<id_maquina>', methods=['POST'])
def acao_producao(id_maquina):
    if 'usuario_logado' not in session:
        return redirect(url_for('login'))  # Proteção de sessão

    conn = get_db_connection()
    cursor = conn.cursor()

    # Verifica se há uma atividade ativa
    atividade = cursor.execute("""
        SELECT * FROM atividades 
        WHERE id_maquina = ? AND status = 'Ativa'
    """, (id_maquina,)).fetchone()

    operador = session.get('usuario_logado')
    agora = datetime.now()
    data = agora.date().isoformat()
    hora = agora.time().strftime('%H:%M:%S')

    if atividade:
        # ENCERRAR PRODUÇÃO
        id_atividade = atividade['id_atividade']
        data_inicio = atividade['data_inicio']
        hora_inicio = atividade['hora_inicio']
        dt_inicio = datetime.strptime(f"{data_inicio} {hora_inicio}", "%Y-%m-%d %H:%M:%S")
        tempo_total = (agora - dt_inicio).total_seconds()

        cursor.execute("""
            UPDATE atividades SET 
                data_fim = ?, 
                hora_fim = ?, 
                operador_fim = ?, 
                status = 'Encerrada',
                tempo_total = ?
            WHERE id_atividade = ?
        """, (data, hora, operador, tempo_total, id_atividade))

        cursor.execute("UPDATE maquinas SET status = 'Parada' WHERE id_maquina = ?", (id_maquina,))
    
    else:
        # INICIAR PRODUÇÃO
        cursor.execute("""
            INSERT INTO atividades (
                id_maquina, data_inicio, hora_inicio, operador_inicio, status
            ) VALUES (?, ?, ?, ?, 'Ativa')
        """, (id_maquina, data, hora, operador))

        cursor.execute("UPDATE maquinas SET status = 'Em produção' WHERE id_maquina = ?", (id_maquina,))

    conn.commit()
    conn.close()
    return '', 204

# Ação Parada
@app.route('/acao_parada/<id_maquina>', methods=['POST'])
def acao_parada(id_maquina):
    if 'usuario_logado' not in session:
        return redirect(url_for('login'))  # Proteção de sessão

    conn = get_db_connection()
    cursor = conn.cursor()

    dados = request.get_json()
    tipo_parada = dados.get('tipo')
    operador = session.get('usuario_logado')
    agora = datetime.now()
    data = agora.date().isoformat()
    hora = agora.time().strftime('%H:%M:%S')

    # Verifica se já existe uma parada ativa desse tipo
    parada_ativa = cursor.execute("""
        SELECT * FROM paradas 
        WHERE id_maquina = ? AND tipo_parada = ? AND status = 'Ativa'
    """, (id_maquina, tipo_parada)).fetchone()

    if parada_ativa:
        # ENCERRAR PARADA
        id_parada = parada_ativa['id_parada']
        data_inicio = parada_ativa['data_inicio']
        hora_inicio = parada_ativa['hora_inicio']
        dt_inicio = datetime.strptime(f"{data_inicio} {hora_inicio}", "%Y-%m-%d %H:%M:%S")
        tempo_total = (agora - dt_inicio).total_seconds()

        cursor.execute("""
            UPDATE paradas SET 
                data_fim = ?, 
                hora_fim = ?, 
                operador_fim = ?, 
                status = 'Encerrada',
                tempo_total = ?
            WHERE id_parada = ?
        """, (data, hora, operador, tempo_total, id_parada))

        cursor.execute("UPDATE maquinas SET status = 'Parada' WHERE id_maquina = ?", (id_maquina,))
    
    else:
        # INICIAR PARADA
        atividade = cursor.execute("""
            SELECT id_atividade FROM atividades 
            WHERE id_maquina = ? AND status = 'Ativa'
        """, (id_maquina,)).fetchone()

        id_atividade = atividade['id_atividade'] if atividade else None

        cursor.execute("""
            INSERT INTO paradas (
                id_maquina, id_atividade, tipo_parada, data_inicio, hora_inicio, operador_inicio, status
            ) VALUES (?, ?, ?, ?, ?, ?, 'Ativa')
        """, (id_maquina, id_atividade, tipo_parada, data, hora, operador))

        cursor.execute("UPDATE maquinas SET status = ? WHERE id_maquina = ?", (f'Em {tipo_parada}', id_maquina))

    conn.commit()
    conn.close()
    return '', 204



if __name__ == '__main__':
    app.run(debug=True)  # Lembre-se de usar debug=False em produção
