import io
import os
import secrets
import threading
from collections import Counter, defaultdict
from functools import wraps
from html import escape as html_escape

import graphviz
from flask import (Flask, abort, flash, jsonify, redirect, render_template,
                   request, send_file, session, url_for)

import backend

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(32))

# Безопасные настройки сессионной cookie.
# SameSite=Strict — главная защита от CSRF в современных браузерах: cookie не
# уходит в кросс-сайтовых запросах вообще, поэтому злоумышленник со стороннего
# сайта не сможет дёрнуть наш POST даже без CSRF-токена. HttpOnly не даёт JS
# украсть cookie через XSS. Secure включаем, если приложение за HTTPS-прокси.
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict',
    SESSION_COOKIE_SECURE=os.getenv('SESSION_COOKIE_SECURE', '0') == '1',
)


# ── CSRF (без внешних зависимостей) ──────────────────────────
#
# Защита: при POST/PUT/PATCH/DELETE требуем валидный csrf_token в форме или в
# заголовке X-CSRF-Token. Токен генерируется один на сессию.
def csrf_token() -> str:
    tok = session.get('_csrf_token')
    if not tok:
        tok = secrets.token_urlsafe(32)
        session['_csrf_token'] = tok
    return tok


@app.context_processor
def _inject_csrf():
    return {'csrf_token': csrf_token}


@app.before_request
def _csrf_protect():
    if request.method not in ('POST', 'PUT', 'PATCH', 'DELETE'):
        return
    # Дать /static спокойно работать (хотя static обычно GET).
    if request.endpoint == 'static':
        return
    expected = session.get('_csrf_token')
    sent = (
        request.form.get('csrf_token')
        or request.headers.get('X-CSRF-Token')
    )
    if not sent and request.is_json:
        body = request.get_json(silent=True) or {}
        sent = body.get('csrf_token') if isinstance(body, dict) else None
    if not expected or not sent or not secrets.compare_digest(expected, sent):
        # Не палим деталей; для JSON-клиента отдаём JSON, для HTML — 400.
        if request.is_json or request.accept_mimetypes.best == 'application/json':
            return jsonify({'error': 'CSRF token missing or invalid'}), 400
        abort(400)


# ── Security headers (defense in depth) ──────────────────────
#
# CSP ограничивает источники, с которых браузер вообще исполнит скрипты и
# подгрузит ресурсы. Даже если где-то remained XSS-вектор, который мы
# пропустили, инлайн-script в нашем HTML вписан "своими руками" — поэтому
# 'unsafe-inline' в script-src нужен для существующих <script>-блоков; чтобы
# его убрать, надо нонсить каждый блок, что для дипломного проекта избыточно.
@app.after_request
def _security_headers(response):
    response.headers.setdefault(
        'Content-Security-Policy',
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "font-src 'self' https://cdn.jsdelivr.net data:; "
        "img-src 'self' data: https://img.shields.io; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'"
    )
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'same-origin')
    return response

# ── Состояние фонового сканирования (единственный пользователь — дипломный стенд) ──
_scan_lock = threading.Lock()
_scan_state: dict = {
    'status': 'idle',   # idle | running | done | error
    'progress': 0,
    'total': 0,
    'current_table': '',
    'current_col': '',
    'results': [],
    'error': None,
}


def _db() -> dict | None:
    """Конфиг БД из сессии или None."""
    return session.get('db_config')


# ── Аутентификация и RBAC ────────────────────────────────────

@app.before_request
def _require_login():
    """Все роуты, кроме /login и /static, требуют аутентификации.
    Намеренно НЕ открываем /logout (его делать без сессии бессмысленно).
    request.endpoint == None (неизвестный URL) тоже валит на логин — это OK."""
    open_endpoints = {'login', 'static'}
    if request.endpoint in open_endpoints:
        return
    if 'user_id' not in session:
        # AJAX/JSON-вызовы получают 401, чтобы фронт мог корректно отреагировать.
        if request.is_json or request.accept_mimetypes.best == 'application/json':
            return jsonify({'error': 'Auth required'}), 401
        return redirect(url_for('login'))


def role_required(*roles):
    """Декоратор: проверяет роль текущего пользователя."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if session.get('user_role') not in roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated
    return decorator


# ══════════════════════════════════════════════
#  АУТЕНТИФИКАЦИЯ
# ══════════════════════════════════════════════

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('scan'))
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        try:
            result = backend.verify_user(username, password)
        except backend.AuthBackendError as e:
            # БД легла — это не неверные креды. В audit log это не пишем,
            # чтобы не забивать дашборд ложными LOGIN_FAILED.
            print(f"Auth backend down: {e}")
            error = 'Сервис временно недоступен, попробуйте позже'
            return render_template('login.html', error=error)

        if result:
            user_id, role = result
            # Защита от session fixation: подменяем session id, выбрасывая всё,
            # что мог положить туда атакующий до логина. csrf_token при следующем
            # обращении пересоздастся.
            session.clear()
            session['user_id']   = user_id
            session['username']  = username
            session['user_role'] = role
            backend.log_auth_event('LOGIN', f'Пользователь {username} ({role}) вошёл в систему')
            return redirect(url_for('scan'))
        else:
            backend.log_auth_event('LOGIN_FAILED', f'Неудачная попытка входа: {username}')
            error = 'Неверный логин или пароль'
    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    username = session.get('username', 'unknown')
    backend.log_auth_event('LOGOUT', f'Пользователь {username} вышел из системы')
    session.clear()
    return redirect(url_for('login'))


# ── Управление пользователями (только admin) ─────────────────

@app.route('/admin/users')
@role_required('admin')
def admin_users():
    users = backend.list_users()
    return render_template('admin/users.html', users=users)


@app.route('/admin/users/create', methods=['POST'])
@role_required('admin')
def admin_users_create():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    role     = request.form.get('role', 'viewer')
    if not username or not password:
        flash('Логин и пароль обязательны', 'danger')
    elif backend.create_user(username, password, role):
        flash(f'Пользователь «{username}» создан', 'success')
    else:
        flash('Ошибка: пользователь уже существует или недопустимая роль', 'danger')
    return redirect(url_for('admin_users'))


@app.route('/admin/users/delete', methods=['POST'])
@role_required('admin')
def admin_users_delete():
    uid = request.form.get('user_id', type=int)
    if not uid or uid == session.get('user_id'):
        flash('Нельзя деактивировать текущего пользователя', 'danger')
    elif backend.delete_user(uid):
        flash('Пользователь деактивирован', 'success')
    else:
        # delete_user возвращает False для последнего admin или несуществующего пользователя.
        flash('Деактивация отклонена: либо это последний активный admin, либо пользователь не найден', 'danger')
    return redirect(url_for('admin_users'))


# ══════════════════════════════════════════════
#  ПОДКЛЮЧЕНИЕ
# ══════════════════════════════════════════════

@app.route('/')
def index():
    return redirect(url_for('scan'))


@app.route('/connect', methods=['GET', 'POST'])
def connect():
    error = None
    if request.method == 'POST':
        cfg = {
            'host':     request.form.get('host', 'localhost'),
            'port':     request.form.get('port', '5432'),
            'dbname':   request.form.get('dbname', ''),
            'user':     request.form.get('user', ''),
            'password': request.form.get('password', ''),
        }
        if request.form.get('ssl') == 'on':
            cfg['sslmode'] = 'require'

        conn = backend.get_connection(cfg)
        if isinstance(conn, str):
            error = conn
        else:
            backend.close_connection(conn, cfg)
            backend.init_db_security(cfg)
            session['db_config'] = cfg
            return redirect(url_for('scan'))

    return render_template('connect.html', error=error)


@app.route('/connect/env')
def connect_env():
    """Вернуть настройки из ENV (для кнопки «Загрузить из Docker»)."""
    return jsonify({
        'host':     os.getenv('DB_HOST', 'db'),
        'port':     os.getenv('DB_PORT', '5432'),
        'dbname':   os.getenv('POSTGRES_DB', 'testdb'),
        'user':     os.getenv('POSTGRES_USER', 'admin'),
        'password': os.getenv('POSTGRES_PASSWORD', 'secret_password'),
    })


@app.route('/connect/test', methods=['POST'])
def connect_test():
    data = request.get_json(force=True)
    cfg = {k: data.get(k, '') for k in ('host', 'port', 'dbname', 'user', 'password')}
    if data.get('ssl'):
        cfg['sslmode'] = 'require'
    conn = backend.get_connection(cfg)
    if isinstance(conn, str):
        return jsonify({'ok': False, 'message': conn})
    backend.close_connection(conn, cfg)
    return jsonify({'ok': True, 'message': 'Соединение установлено!'})


@app.route('/connect/disconnect', methods=['POST'])
def disconnect():
    session.pop('db_config', None)
    return redirect(url_for('connect'))


# ══════════════════════════════════════════════
#  СКАНИРОВАНИЕ
# ══════════════════════════════════════════════

@app.route('/scan')
def scan():
    cfg = _db()
    if not cfg:
        return redirect(url_for('connect'))
    tables = backend.get_all_tables(cfg)
    custom = session.get('custom_patterns', {})
    return render_template('scan.html',
                           tables=tables,
                           patterns=backend.PII_PATTERNS,
                           custom_patterns=custom,
                           db_name=cfg.get('dbname', ''))


@app.route('/scan/metadata')
def scan_metadata():
    cfg = _db()
    if not cfg:
        return jsonify({'error': 'Not connected'}), 401
    hints = backend.scan_metadata_for_hints(cfg)
    return jsonify(hints)


@app.route('/scan/start', methods=['POST'])
def scan_start():
    cfg = _db()
    if not cfg:
        return jsonify({'error': 'Not connected'}), 401

    data = request.get_json(force=True)
    excluded       = data.get('excluded_tables', [])
    selected_names = data.get('selected_patterns', list(backend.PII_PATTERNS.keys()))
    custom         = data.get('custom_patterns', {})
    limit_rows     = int(data.get('limit_rows', 2000))

    all_pats     = {**backend.PII_PATTERNS, **custom}
    active_pats  = {k: all_pats[k] for k in selected_names if k in all_pats}

    with _scan_lock:
        if _scan_state['status'] == 'running':
            return jsonify({'error': 'Scan already running'}), 409
        _scan_state.update(status='running', progress=0, total=0,
                           current_table='', current_col='',
                           results=[], error=None)

    def _run():
        def _cb(idx, total, table, col):
            with _scan_lock:
                _scan_state.update(progress=idx, total=total,
                                   current_table=table, current_col=col)
        try:
            results = backend.scan_database(
                excluded_tables=excluded,
                active_patterns=active_pats,
                db_config=cfg,
                limit_rows=limit_rows,
                progress_callback=_cb,
            )
            backend.log_event('SCAN', cfg.get('dbname', ''),
                              f'Найдено {len(results)} объектов')
            with _scan_lock:
                _scan_state.update(results=results, status='done')
        except Exception as exc:
            with _scan_lock:
                _scan_state.update(status='error', error=str(exc))

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({'ok': True})


@app.route('/scan/status')
def scan_status():
    with _scan_lock:
        total = _scan_state['total']
        pct   = int(_scan_state['progress'] / total * 100) if total else 0
        return jsonify({
            'status':        _scan_state['status'],
            'progress':      pct,
            'current_table': _scan_state['current_table'],
            'current_col':   _scan_state['current_col'],
            'count':         len(_scan_state['results']),
            'error':         _scan_state['error'],
        })


# ══════════════════════════════════════════════
#  РЕЗУЛЬТАТЫ И ОБЕЗЛИЧИВАНИЕ
# ══════════════════════════════════════════════

@app.route('/results')
def results():
    with _scan_lock:
        findings = list(_scan_state['results'])
        status   = _scan_state['status']

    if not findings and status not in ('done',):
        return redirect(url_for('scan'))

    type_counts  = dict(Counter(f['type']  for f in findings))
    table_counts = dict(Counter(f['table'] for f in findings))
    validated_count = sum(1 for f in findings if f.get('validated') is True)

    groups = defaultdict(int)
    for f in findings:
        groups[(f['table'], f['column'], f['type'])] += 1
    summary = [{'table': t, 'column': c, 'type': tp, 'count': n}
               for (t, c, tp), n in sorted(groups.items())]

    return render_template('results.html',
                           findings=findings[:500],
                           total=len(findings),
                           type_counts=type_counts,
                           table_counts=table_counts,
                           summary=summary,
                           validated_count=validated_count)


@app.route('/results/mask', methods=['POST'])
@role_required('admin')
def results_mask():
    cfg = _db()
    if not cfg:
        return jsonify({'error': 'Not connected'}), 401
    data = request.get_json(force=True)
    mode = data.get('mode', 'mask')
    with _scan_lock:
        findings = list(_scan_state['results'])
    count = backend.mask_data(findings, mode=mode, db_config=cfg)
    with _scan_lock:
        _scan_state.update(results=[], status='idle')
    return jsonify({'ok': True, 'count': count})


@app.route('/results/dump', methods=['POST'])
@role_required('admin')
def results_dump():
    cfg = _db()
    if not cfg:
        return jsonify({'error': 'Not connected'}), 401
    data = request.get_json(force=True)
    mode = data.get('mode', 'mask')
    with _scan_lock:
        findings = list(_scan_state['results'])
    path = backend.generate_sanitized_dump(findings, mode=mode, db_config=cfg)
    if not path:
        return jsonify({'error': 'Ошибка генерации дампа'}), 500
    return send_file(path, as_attachment=True,
                     download_name='sanitized_dump.sql', mimetype='application/sql')


@app.route('/results/pdf')
def results_pdf():
    with _scan_lock:
        findings = list(_scan_state['results'])
    pdf_bytes = backend.create_pdf_report(findings)
    return send_file(io.BytesIO(pdf_bytes), as_attachment=True,
                     download_name='security_report.pdf', mimetype='application/pdf')


# ══════════════════════════════════════════════
#  ИССЛЕДОВАНИЕ БД
# ══════════════════════════════════════════════

@app.route('/explore')
def explore():
    cfg = _db()
    if not cfg:
        return redirect(url_for('connect'))

    tables_info, relations = backend.get_db_schema_info(cfg)
    svg = ''
    if tables_info:
        g = graphviz.Digraph()
        g.attr(rankdir='LR', splines='ortho')
        g.attr('node', shape='plaintext')
        for tname, pk in tables_info.items():
            # ER-метки рендерятся как HTML-like labels Graphviz, а итоговый SVG
            # вставляется в страницу через {{ svg | safe }}. Без escape любая
            # таблица/PK с символом < в имени превращается в stored XSS.
            safe_tname = html_escape(str(tname))
            pk_label = f'PK: {html_escape(str(pk))}' if pk else 'no PK'
            label = (
                f'<<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" BGCOLOR="#E3F2FD">'
                f'<TR><TD><B>{safe_tname}</B></TD></TR>'
                f'<TR><TD ALIGN="LEFT"><FONT POINT-SIZE="10" COLOR="#555">{pk_label}</FONT></TD></TR>'
                f'</TABLE>>'
            )
            g.node(tname, label=label)
        for s, t in relations:
            g.edge(s, t, label='FK', color='#888', style='dashed')
        try:
            svg = g.pipe(format='svg').decode('utf-8')
        except Exception as exc:
            svg = f'<p class="text-danger">Graphviz error: {exc}</p>'

    return render_template('explore.html',
                           svg=svg,
                           table_names=list(tables_info.keys()) if tables_info else [],
                           db_name=cfg.get('dbname', ''))


@app.route('/explore/table/<name>')
def explore_table(name):
    cfg = _db()
    if not cfg:
        return jsonify({'error': 'Not connected'}), 401
    stats  = backend.get_table_statistics(name, db_config=cfg)
    sample = backend.get_table_sample(name, limit=5, db_config=cfg)
    return jsonify({
        'rows':    stats['rows'],
        'size':    stats['size'],
        'columns': stats['columns'],
        'sample':  sample,
    })


# ══════════════════════════════════════════════
#  УПРАВЛЕНИЕ РАЗМЕТКОЙ (DATA GOVERNANCE)
# ══════════════════════════════════════════════

@app.route('/governance', methods=['GET', 'POST'])
def governance():
    cfg = _db()
    if not cfg:
        return redirect(url_for('connect'))

    if request.method == 'POST':
        if session.get('user_role') not in ('admin', 'analyst'):
            return jsonify({'error': 'Недостаточно прав'}), 403
        data    = request.get_json(force=True)
        updates = data.get('updates', [])
        ok      = backend.save_batch_settings(updates, cfg)
        return jsonify({'ok': ok})

    cols_info        = backend.get_db_schema_details(cfg)
    current_settings = backend.get_column_settings(cfg)
    rows = []
    for t_name, c_name, c_type in cols_info:
        s = current_settings.get((t_name, c_name), {})
        rows.append({
            'table':    t_name,
            'column':   c_name,
            'db_type':  c_type,
            'status':   s.get('status', 'AUTO'),
            'pii_type': s.get('type') or '',
        })

    return render_template('governance.html',
                           rows=rows,
                           pii_types=list(backend.PII_PATTERNS.keys()))


# ══════════════════════════════════════════════
#  ЖУРНАЛ АУДИТА
# ══════════════════════════════════════════════

@app.route('/audit')
def audit():
    cfg      = _db()
    app_logs = backend.get_audit_logs()
    return render_template('audit.html',
                           app_logs=app_logs,
                           connected=cfg is not None)


@app.route('/audit/db')
def audit_db():
    cfg = _db()
    if not cfg:
        return jsonify({'error': 'Not connected'}), 401
    conn = backend.get_connection(cfg)
    if isinstance(conn, str):
        return jsonify({'error': conn}), 500
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT event_time, db_user, app_user, client_ip,
                   event_class, table_name, operation, changed_cols, details
            FROM pii_guard.audit_log
            ORDER BY event_time DESC LIMIT 100
        """)
        rows = cur.fetchall()
        cur.close()
        return jsonify([{
            'time':         str(r[0]),
            'db_user':      r[1] or '',
            'app_user':     r[2] or '',
            'client_ip':    r[3] or '',
            'event_class':  r[4] or 'DATA',
            'table':        r[5] or '',
            'operation':    r[6] or '',
            'changed_cols': r[7] or '',
            'details':      r[8] or '',
        } for r in rows])
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500
    finally:
        backend.close_connection(conn, cfg)


# ══════════════════════════════════════════════
#  ДАШБОРД БЕЗОПАСНОСТИ
# ══════════════════════════════════════════════

@app.route('/security')
def security():
    cfg = _db()
    stats  = backend.get_security_stats(cfg) if cfg else {}
    return render_template('security.html', stats=stats, connected=cfg is not None)


@app.route('/security/verify')
def security_verify():
    cfg = _db()
    if not cfg:
        return jsonify({'ok': False, 'message': 'Нет подключения к БД'}), 400
    result = backend.verify_audit_chain(cfg)
    return jsonify(result)


@app.route('/security/events')
def security_events():
    cfg = _db()
    if not cfg:
        return jsonify({'error': 'Not connected'}), 401
    operation = request.args.get('operation') or None
    db_user   = request.args.get('db_user') or None
    date_from = request.args.get('date_from') or None
    date_to   = request.args.get('date_to') or None
    offset    = int(request.args.get('offset', 0))
    rows = backend.get_security_events(
        operation=operation, db_user=db_user,
        date_from=date_from, date_to=date_to,
        limit=50, offset=offset, db_config=cfg
    )
    return jsonify([{
        'event_id':  r[0],
        'time':      str(r[1]),
        'db_user':   r[2] or '',
        'app_user':  r[3] or '',
        'client_ip': r[4] or '',
        'operation': r[5] or '',
        'details':   r[6] or '',
        'row_hash':  (r[7] or '')[:16] + '…',
    } for r in rows])


# ══════════════════════════════════════════════
#  КАСТОМНЫЕ ПАТТЕРНЫ (храним в сессии)
# ══════════════════════════════════════════════

@app.route('/patterns/add', methods=['POST'])
def pattern_add():
    data  = request.get_json(force=True)
    name  = data.get('name', '').strip()
    regex = data.get('regex', '').strip()
    if not name or not regex:
        return jsonify({'ok': False, 'error': 'Нужны name и regex'})
    custom      = session.get('custom_patterns', {})
    custom[name] = regex
    session['custom_patterns'] = custom
    return jsonify({'ok': True})


@app.route('/patterns/delete', methods=['POST'])
def pattern_delete():
    data  = request.get_json(force=True)
    name  = data.get('name', '')
    custom = session.get('custom_patterns', {})
    custom.pop(name, None)
    session['custom_patterns'] = custom
    return jsonify({'ok': True})


# ══════════════════════════════════════════════
# Инициализация при импорте модуля — нужна и для gunicorn (он не выполняет
# __main__-блок). Защищаем флагом, чтобы воркеры gunicorn не дрались за инит.
_INIT_DONE = False


def _bootstrap_once():
    global _INIT_DONE
    if _INIT_DONE:
        return
    _INIT_DONE = True
    try:
        backend.init_db_security()
        backend.init_auth_db()
    except Exception as _e:
        print(f"Startup init warning: {_e}")


_bootstrap_once()


if __name__ == '__main__':
    # Локальный режим (flask dev server). В проде gunicorn импортирует
    # модуль и пользуется _bootstrap_once() выше.
    try:
        backend.init_db_security()
        backend.init_auth_db()
    except Exception as _e:
        print(f"Startup init warning: {_e}")
    app.run(host='0.0.0.0', port=5000, debug=False)
