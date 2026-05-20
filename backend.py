import psycopg2
from psycopg2 import sql, pool
import re
import os
import datetime
import subprocess
import sqlite3
import tempfile
import threading
from faker import Faker
from fpdf import FPDF
from werkzeug.security import generate_password_hash, check_password_hash
import validators as _validators

# Инициализируем генератор (ru_RU - чтобы создавал российские данные)
fake = Faker('ru_RU')

# Читаем конфигурацию из переменных окружения (Docker-friendly)
DB_CONFIG = {
    "dbname": os.getenv("POSTGRES_DB", "testdb"),
    "user": os.getenv("POSTGRES_USER", "admin"),
    "password": os.getenv("POSTGRES_PASSWORD", "secret_password"),
    "host": os.getenv("DB_HOST", "localhost"),
    "port": os.getenv("DB_PORT", "5432")
}

# --- КОНСТАНТЫ И ПАТТЕРНЫ ---

# 1. СТОП-СЛОВА (Для умного фильтра)
# Если название колонка содержит эти слова, мы считаем её технической и пропускаем (AUTO mode)
SKIP_COLUMN_KEYWORDS = [
    # Технические даты (обычно это метаданные, а не ДР)
    "_at", "_on", "created", "updated", "deleted", "timestamp", "version", 
    "last_login", "expire", "valid_until", "date_joined", "audit",
    # Технические ID (которые выглядят как цифры, но не являются PII)
    "_id", "uuid", "guid", "ref_key", "foreign_key", "order_num", "transaction",
    "invoice", "sku", "ean", "code", "qty", "count"
]

# 2. ПАТТЕРНЫ ПОИСКА (RegEx) - Extended Version
#
# Важно про порядок: scan_database делает break при ПЕРВОМ матче, поэтому
# регексы упорядочены от самых длинных/специфичных к коротким. Если поставить
# INN10 перед OGRN13, то OGRN '1234567890123' уйдёт в INN10 как первое
# попавшееся, и тип определится случайно. \b на цифровых паттернах тоже
# обманчив (буква перед цифрой считается word-boundary), поэтому везде, где
# матчим только цифры, используем (?<!\d)…(?!\d) — иначе один и тот же
# 16-значный номер ОМС подсветится и как Passport (4+6), и как INN12.
PII_PATTERNS = {
    # --- Базовые контакты ---
    "Email": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
    # Раньше регекс ловил ведущую '7' внутри любого 11-значного числа (ИНН/ОГРН).
    # (?<!\d) гарантирует, что перед +7/8/7 нет другой цифры; (?!\d) — что после
    # хвоста тоже нет цифры (иначе кусок длинного номера тоже считался телефоном).
    "Phone (RU)": r"(?<!\d)(?:\+7|8|7)[\s\(-]*\d{3}[\s\)-]*\d{3}[\s-]*\d{2}[\s-]*\d{2}(?!\d)",

    # --- Самые длинные числовые ID идут ПЕРВЫМИ, чтобы их не перехватил
    # более короткий регекс на префикс. ---
    "OMS (Medical Policy)":  r"(?<!\d)\d{16}(?!\d)",      # 16 цифр — полис ОМС
    "OGRNIP (Entrepreneur)": r"(?<!\d)\d{15}(?!\d)",      # 15 цифр — ОГРНИП
    "OGRN (Company)":        r"(?<!\d)\d{13}(?!\d)",      # 13 цифр — ОГРН
    "Credit Card":           r"(?<!\d)(?:\d{4}[ -]?){3,4}\d{1,4}(?!\d)",  # 13-19 цифр с разделителями
    "INN (Individual 12)":   r"(?<!\d)\d{12}(?!\d)",      # 12 цифр — ИНН физлица
    "SNILS":                 r"(?<!\d)\d{3}[ -]?\d{3}[ -]?\d{3}[ -]?\d{2}(?!\d)",  # 11 цифр
    "Passport (RU Internal)":     r"(?<!\d)\d{4}[\s-]?\d{6}(?!\d)",   # 10 цифр
    "INN (Company 10)":           r"(?<!\d)\d{10}(?!\d)",             # 10 цифр
    "Passport (RU International)": r"(?<!\d)\d{2}[\s]?\d{7}(?!\d)",   # 9 цифр
    "KPP (Tax Reason Code)":      r"(?<!\d)\d{9}(?!\d)",              # 9 цифр

    # --- Документы со смешанным алфавитом — порядок не критичен ---
    "Driver License (RU)":   r"\b\d{2}[\s]?[A-ZА-Я0-9]{2}[\s]?\d{6}\b",
    "Birth Certificate (RU)": r"[IVX]{1,3}[\-][А-Я]{2}\s\d{6}",

    # --- Финансы (нечисловые) ---
    "IBAN (Int. Bank Account)": r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b",
    "Bitcoin Wallet": r"\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b",
    "Ethereum Wallet": r"\b0x[a-fA-F0-9]{40}\b",

    # --- IT и Безопасность ---
    "IPv4 Address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "MAC Address": r"\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b",
    "JWT Token": r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
    "AWS API Key": r"AKIA[0-9A-Z]{16}",
    "Private Key (Header)": r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
    "UUID / GUID": r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",

    # --- Соцсети и Гео ---
    "Social: Telegram": r"(?:t\.me\/|@)[a-zA-Z0-9_]{5,}",
    "Social: VK": r"(?:vk\.com\/)[a-zA-Z0-9_.]+",
    "Geo Coordinates": r"\b-?\d{1,3}\.\d+,\s*-?\d{1,3}\.\d+\b",

    # --- Секреты и Пароли ---
    "Password Hash (BCrypt)": r"^\$2[ayb]\$.{56}$",
    "Password Hash (SHA256)": r"\b[a-fA-F0-9]{64}\b",  # 64 hex
    "Password Hash (MD5)":    r"\b[a-fA-F0-9]{32}\b",  # 32 hex — после SHA256, иначе SHA-фрагменты ловит MD5
    "Generic API Key / Secret": r"\b(?=[a-zA-Z0-9]*[A-Z])(?=[a-zA-Z0-9]*[a-z])(?=[a-zA-Z0-9]*[0-9])[a-zA-Z0-9]{32,60}\b",

    # --- Сложные проверки (Контекстные) ---
    "FIO (RU)": r"\b[А-ЯЁ][а-яё]{1,20}\s+[А-ЯЁ][а-яё]{1,20}\s+[А-ЯЁ][а-яё]{1,20}\b",
    "Date of Birth": r"\b(?:0[1-9]|[12][0-9]|3[01])[\.\/-](?:0[1-9]|1[012])[\.\/-](?:19|20)\d{2}\b",

    # --- Универсальный (для ручной разметки) ---
    "Generic / Any Content": r".+"
}

# 3. ПОДОЗРИТЕЛЬНЫЕ НАЗВАНИЯ (Для Metadata Profiling)
SUSPICIOUS_NAMES = {
    "email": "Email", "mail": "Email",
    "phone": "Phone (RU)", "mobile": "Phone (RU)",
    "passport": "Passport (RU)", "pass_doc": "Passport (RU)",
    "inn": "INN (Individual)",
    "snils": "SNILS",
    "credit_card": "Credit Card", "card_num": "Credit Card",
    "fio": "FIO (RU)", "full_name": "FIO (RU)", "name": "FIO (RU)", "lastname": "FIO (RU)",
    "birth": "Date of Birth", "dob": "Date of Birth",
    "address": "Address (Risk)", "city": "Address (Risk)", "region": "Address (Risk)"
}

# --- БАЗОВЫЕ ФУНКЦИИ БД ---

# --- УПРАВЛЕНИЕ ПУЛОМ СОЕДИНЕНИЙ ---

_pool_cache: dict = {}
_pool_lock = threading.Lock()

def _pool_key(db_config: dict) -> tuple:
    return (db_config.get('host'), db_config.get('port'),
            db_config.get('dbname'), db_config.get('user'))

def get_db_pool(db_config: dict):
    """Возвращает пул соединений из кэша или создаёт новый."""
    key = _pool_key(db_config)
    with _pool_lock:
        if key not in _pool_cache:
            try:
                _pool_cache[key] = pool.ThreadedConnectionPool(1, 20, **db_config)
            except Exception as e:
                print(f"Pool Creation Error: {e}")
                return None
        return _pool_cache[key]

def get_connection(db_config=None):
    """Получает соединение из пула с механизмом самоисцеления."""
    target_conf = db_config if db_config else DB_CONFIG
    try:
        db_pool = get_db_pool(target_conf)
        if not db_pool:
            return "Error creating connection pool"
        conn = db_pool.getconn()
        return conn
    except pool.PoolError:
        print("⚠️ Pool exhausted! Performing self-healing...")
        key = _pool_key(target_conf)
        with _pool_lock:
            if key in _pool_cache:
                try:
                    _pool_cache[key].closeall()
                except Exception:
                    pass
                del _pool_cache[key]
        db_pool = get_db_pool(target_conf)
        if db_pool:
            try:
                return db_pool.getconn()
            except Exception as e:
                return f"Critical Pool Error after reset: {e}"
        return "Error creating connection pool after reset"
    except Exception as e:
        return str(e)

def close_connection(conn, db_config=None):
    """
    ВАЖНО: Не закрывает соединение, а возвращает его в пул!
    """
    target_conf = db_config if db_config else DB_CONFIG
    try:
        db_pool = get_db_pool(target_conf)
        if db_pool and conn:
            db_pool.putconn(conn)
    except Exception as e:
        print(f"Error returning connection to pool: {e}")

def _pg_sec_event(conn, event: str, details: str = None):
    """Записывает событие безопасности приложения в pii_guard.audit_log."""
    try:
        cur = conn.cursor()
        cur.execute("CALL pii_guard.log_security_event(%s, %s)", (event, details))
        conn.commit()
        cur.close()
    except Exception as e:
        print(f"Security event log error ({event}): {e}")

def get_all_tables(db_config=None):
    """Получает список всех таблиц в схеме public"""
    conn = get_connection(db_config) # <--- Передаем конфиг
    if isinstance(conn, str): return []
    
    cur = conn.cursor()
    cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")
    tables = [row[0] for row in cur.fetchall()]
    
    cur.close()
    close_connection(conn, db_config) # <--- Теперь db_config известен
    return tables

# --- УПРАВЛЕНИЕ НАСТРОЙКАМИ (DATA GOVERNANCE) ---

def init_settings_table(db_config=None):
    """Создает таблицу для хранения ручной разметки колонок"""
    conn = get_connection(db_config) # <--- Передаем конфиг
    if isinstance(conn, str): return
    
    cur = conn.cursor()
    try:
        cur.execute("CREATE SCHEMA IF NOT EXISTS pii_guard;")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS pii_guard.column_settings (
                table_name TEXT,
                column_name TEXT,
                status TEXT, -- 'AUTO', 'IGNORE', 'FORCE_PII'
                pii_type TEXT, -- Если FORCE_PII, то какой тип (например 'Email')
                updated_at TIMESTAMP DEFAULT NOW(),
                PRIMARY KEY (table_name, column_name)
            );
        """)
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"Settings Init Error: {e}")
    finally:
        cur.close()
        close_connection(conn, db_config) # <--- Теперь db_config известен

def get_column_settings(db_config=None):
    """Возвращает словарь настроек {(table, col): {'status': ..., 'type': ...}}"""
    # init_settings_table вызовем внутри init_db_security, тут можно пропустить для скорости
    conn = get_connection(db_config)
    if isinstance(conn, str): return {}
    cur = conn.cursor()
    try:
        cur.execute("SELECT table_name, column_name, status, pii_type FROM pii_guard.column_settings")
        rows = cur.fetchall()
        settings = {}
        for r in rows:
            settings[(r[0], r[1])] = {"status": r[2], "type": r[3]}
        return settings
    except Exception as e:
        print(f"Settings load error: {e}")
        return {}
    finally:
        cur.close()
        close_connection(conn, db_config)

VALID_STATUSES = {'AUTO', 'IGNORE', 'FORCE_PII'}

def save_batch_settings(updates, db_config=None):
    """
    Массовое сохранение настроек.
    updates: список словарей [{'table':..., 'col':..., 'status':..., 'type':...}]
    """
    conn = get_connection(db_config)
    if isinstance(conn, str): return False
    cur = conn.cursor()
    try:
        query = """
            INSERT INTO pii_guard.column_settings (table_name, column_name, status, pii_type, updated_at)
            VALUES (%s, %s, %s, %s, NOW())
            ON CONFLICT (table_name, column_name)
            DO UPDATE SET status = EXCLUDED.status, pii_type = EXCLUDED.pii_type, updated_at = NOW();
        """
        # Фильтруем записи с недопустимым статусом перед сохранением
        valid_updates = []
        for x in updates:
            if x['status'] not in VALID_STATUSES:
                print(f"⚠️ Недопустимый статус '{x['status']}' для {x['table']}.{x['col']}, пропускаем.")
                continue
            valid_updates.append(x)

        data = [(x['table'], x['col'], x['status'], x['type']) for x in valid_updates]
        cur.executemany(query, data)
        cur.execute("CALL pii_guard.log_security_event(%s, %s)", (
            'GOVERNANCE_UPDATE',
            f'Обновлено {len(valid_updates)} правил разметки колонок'
        ))
        conn.commit()
        return True
    except Exception as e:
        print(e)
        conn.rollback()
        return False
    finally:
        cur.close()
        close_connection(conn, db_config)

# --- ЯДРО СКАНИРОВАНИЯ ---

def is_technical_column(col_name):
    """Эвристика: проверяет, похоже ли название на техническое поле"""
    col_lower = col_name.lower()
    for kw in SKIP_COLUMN_KEYWORDS:
        if kw in col_lower:
            # Исключение: если есть слово 'birth', то это не техническая дата
            if 'birth' in col_lower or 'dob' in col_lower:
                return False
            return True
    return False

def check_date_context(date_str):
    """
    Проверяет год в дате.
    True  -> Похоже на дату рождения (1920 — текущий год включительно).
    False -> Будущая дата или слишком давняя.
    Убрали жёсткий отсечатель «последние 5 лет» — он отбрасывал реальные ДР молодых людей.
    """
    try:
        years = re.findall(r"(?:19|20)\d{2}", date_str)
        if not years: return False

        year = int(years[0])
        current_year = datetime.datetime.now().year

        # Будущие даты точно не ДР
        if year > current_year: return False
        # Слишком старая дата
        if year < 1920: return False

        return True
    except Exception:
        return False

def scan_database(excluded_tables=None, active_patterns=None, db_config=None, limit_rows=2000, progress_callback=None):
    """
    progress_callback(current, total, table, col) — вызывается на каждом шаге,
    чтобы UI мог показывать прогресс в реальном времени.
    """
    if excluded_tables is None: excluded_tables = []
    if active_patterns is None: active_patterns = PII_PATTERNS.copy()

    # 1. Получаем настройки (Ручную разметку)
    settings = get_column_settings(db_config)

    # 2. Получаем список всех текстовых/дата/json колонок
    conn = get_connection(db_config)
    if isinstance(conn, str): return []
    cur = conn.cursor()
    cur.execute("""
        SELECT table_name, column_name
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND data_type IN (
            'character varying', 'text',
            'date', 'timestamp without time zone', 'timestamp with time zone',
            'json', 'jsonb'
          );
    """)
    all_columns = cur.fetchall()

    findings = []
    total_cols = len(all_columns)
    print(f"🚀 Старт умного сканирования. Всего колонок: {total_cols}")

    for idx, (table, col) in enumerate(all_columns):
        if progress_callback:
            progress_callback(idx, total_cols, table, col)
        if table in excluded_tables: continue
        
        # --- ШАГ 1: ПРОВЕРКА НАСТРОЕК (Data Governance) ---
        col_setting = settings.get((table, col), {})
        status = col_setting.get('status', 'AUTO')
        
        if status == 'IGNORE':
            continue # Рукой помечено "Игнорировать"
            
        if status == 'AUTO':
            # Автоматический режим: применяем эвристику стоп-слов
            if is_technical_column(col):
                continue
                
        # --- ШАГ 2: ПОДГОТОВКА ПАТТЕРНОВ ---
        # Если FORCE_PII, ищем только конкретный тип
        target_patterns = active_patterns
        if status == 'FORCE_PII':
            forced_type = col_setting.get('type')
            if forced_type and forced_type in PII_PATTERNS:
                target_patterns = {forced_type: PII_PATTERNS[forced_type]}
        
        # --- ШАГ 3: ЧТЕНИЕ ДАННЫХ ---
        # Используем ctid вместо id — таблица может вообще не иметь колонки id
        # (составной PK, user_id и т.п.). ctid однозначно идентифицирует физическую строку.
        try:
            query = sql.SQL("SELECT ctid::text, {}::text FROM {} WHERE {} IS NOT NULL LIMIT {}").format(
                sql.Identifier(col),
                sql.Identifier(table),
                sql.Identifier(col),
                sql.Literal(limit_rows)
            )
            cur.execute(query)
            rows = cur.fetchall()
        except Exception as e:
            print(f"⚠️ Ошибка чтения {table}.{col}: {e}")
            conn.rollback()  # иначе соединение останется в aborted tx
            continue

        # --- ШАГ 4: АНАЛИЗ КОНТЕНТА ---
        for row_id, val in rows:
            text_val = str(val)

            for p_name, p_regex in target_patterns.items():
                m = re.search(p_regex, text_val)
                if not m:
                    continue

                # Контекстная проверка для Дат — раньше check_date_context
                # парсил всё поле и брал первый год, поэтому "created 2025, born
                # 1980" проверялся по 2025. Теперь смотрим строго на матч.
                if p_name == "Date of Birth":
                    if not check_date_context(m.group(0)):
                        continue

                findings.append({
                    "table":     table,
                    "column":    col,
                    "id":        row_id,
                    "type":      p_name,
                    "value":     text_val,
                    "validated": _validators.validate(p_name, text_val),
                })
                break # Нашли угрозу -> следующая строка

    _pg_sec_event(conn, 'SCAN',
        f'Сканирование завершено: {len(findings)} находок в {total_cols} колонках')
    cur.close()
    close_connection(conn, db_config)
    return findings

def scan_metadata_for_hints(db_config=None):
    """Анализ названий колонок (Metadata Profiling)"""
    conn = get_connection(db_config) # <--- Передаем конфиг
    if isinstance(conn, str): return []
    
    cur = conn.cursor()
    cur.execute("""
        SELECT table_name, column_name 
        FROM information_schema.columns 
        WHERE table_schema = 'public'
    """)
    columns = cur.fetchall()
    hints = []
    
    for table, col in columns:
        col_lower = col.lower()
        for keyword, pii_type in SUSPICIOUS_NAMES.items():
            if keyword in col_lower:
                hints.append({
                    "table": table,
                    "column": col,
                    "suspected_type": pii_type
                })
                break
    cur.close()
    close_connection(conn, db_config) # <--- Теперь db_config известен
    return hints

# --- ФУНКЦИИ БЕЗОПАСНОСТИ И ОБЕЗЛИЧИВАНИЯ ---

def init_db_security(db_config=None):
    """Применяет SQL-скрипт защиты и инициализирует настройки"""
    # 1. Создаем таблицу настроек
    # (в идеале init_settings_table тоже должна принимать конфиг, но пока опустим для краткости)
    init_settings_table(db_config)
    
    # 2. Накатываем логику аудита и маскирования
    conn = get_connection(db_config) # <--- Передаем конфиг
    if isinstance(conn, str): return
    cur = conn.cursor()
    try:
        # Абсолютный путь — иначе при смене CWD (тесты, IDE, gunicorn) open()
        # ловил FileNotFoundError, и init молча падал.
        sql_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "init_db_logic.sql")
        with open(sql_path, "r", encoding="utf-8") as f:
            cur.execute(f.read())
        
        # Включаем аудит для всех таблиц
        cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")
        tables = [row[0] for row in cur.fetchall()]
        for table in tables:
            cur.execute("CALL pii_guard.enable_audit(%s)", (table,))
            
        conn.commit()
        print(f"🛡️ Безопасность БД активирована.")
    except Exception as e:
        conn.rollback()
        print(f"❌ Ошибка инициализации DB Security: {e}")
    finally:
        cur.close()
        close_connection(conn, db_config)

def mask_data(findings, mode='mask', db_config=None):
    """Обезличивание данных (SQL mask или Python Faker)"""
    if mode not in ('mask', 'fake'):
        print(f"⚠️ Неверный режим: '{mode}', используется 'mask'")
        mode = 'mask'

    conn = get_connection(db_config)
    if isinstance(conn, str): return 0

    cur = conn.cursor()
    count = 0
    try:
        if mode == 'mask':
            # Быстрый SQL способ
            unique_tasks = set((f['table'], f['column']) for f in findings)
            for table, col in unique_tasks:
                # Безопасный вызов процедуры через параметры (защита от инъекций в именах)
                cur.execute("CALL pii_guard.fast_mask(%s, %s)", (table, col))
            count = len(findings)
        else:
            # Умный Faker способ
            for item in findings:
                table = item['table']
                col = item['column']
                row_id = item['id']
                pii_type = item['type']
                
                # ... (Генерация new_value - оставляем как было) ...
                new_value = "****"
                if pii_type == 'Email': new_value = fake.email()
                elif 'Phone' in pii_type: new_value = f"+79{fake.random_int(100000000, 999999999)}"
                elif 'Passport' in pii_type: new_value = f"{fake.random_int(1000, 9999)} {fake.random_int(100000, 999999)}"
                elif 'Credit' in pii_type: new_value = fake.credit_card_number()
                elif 'INN' in pii_type: new_value = str(fake.random_int(100000000000, 999999999999))
                elif 'FIO' in pii_type: new_value = fake.name()
                elif 'Date' in pii_type: new_value = fake.date_of_birth().strftime("%d.%m.%Y")
                elif 'Address' in pii_type: new_value = fake.address()
                else: new_value = fake.word()

                try:
                    # row_id здесь — это ctid из scan_database (тип tid).
                    # Каст явный, чтобы apk был валиден для любой таблицы независимо от наличия id.
                    query = sql.SQL("UPDATE {} SET {} = %s WHERE ctid = %s::tid").format(
                        sql.Identifier(table),
                        sql.Identifier(col)
                    )
                    cur.execute(query, (new_value, row_id))
                    count += 1
                except Exception as e:
                    print(f"⚠️ Ошибка маскирования {table}.{col} ctid={row_id}: {e}")
                    conn.rollback()
                    
        # Раньше MASS_MASKING-событие писалось только внутри fast_mask на каждую
        # колонку, а сводное событие — только в fake-ветке. Из-за этого счётчик
        # MASS_MASKING на дашборде безопасности всегда равнялся 0.
        if mode == 'fake':
            _pg_sec_event(conn, 'MASS_FAKER',
                f'Синтетическая замена {count} записей (Faker)')
        else:
            _pg_sec_event(conn, 'MASS_MASKING',
                f'SQL-маскирование {count} записей в {len(unique_tasks)} колонках')
        conn.commit()
        db_name_log = db_config['dbname'] if db_config else "unknown_db"
        log_event("MASK", db_name_log, f"Обезличено {count} записей ({mode})")
    except Exception as e:
        conn.rollback()
        print(f"❌ Ошибка маскирования: {e}")
        count = 0
    finally:
        cur.close()
        close_connection(conn, db_config)
    return count

def _validate_identifier(name):
    """Проверяет, что имя БД/таблицы содержит только безопасные символы."""
    if not re.match(r'^[a-zA-Z0-9_]+$', name):
        raise ValueError(f"Небезопасное имя объекта БД: '{name}'")
    return name

def generate_sanitized_dump(findings, mode='mask', db_config=None):
    """
    Создает безопасную копию БД, обезличивает её и делает дамп.
    Исключает таблицу аудита из дампа!
    """
    target_conf = db_config if db_config else DB_CONFIG

    original_db = _validate_identifier(target_conf['dbname'])
    temp_db = _validate_identifier(f"{original_db}_anon_temp")
    # Хардкод /tmp ломал работу на Windows и при параллельных дампах двух админов.
    # NamedTemporaryFile с delete=False даёт уникальный путь и в Linux, и в Windows.
    _dump_handle = tempfile.NamedTemporaryFile(
        mode='w', suffix='.sql', prefix=f'pii_dump_{original_db}_', delete=False
    )
    dump_file = _dump_handle.name
    _dump_handle.close()
    
    # Коннект к системной базе postgres для клонирования
    admin_config = target_conf.copy()
    admin_config['dbname'] = 'postgres'
    
    # Важно: для клонирования нужно подключиться к postgres, а не к целевой БД
    try:
        conn = psycopg2.connect(**admin_config)
        conn.autocommit = True
        cur = conn.cursor()
    except Exception as e:
        print(f"Connection error: {e}")
        return None
    
    try:
        print(f"📦 Начало создания безопасного дампа...")
        
        # 1. Кикаем подключения к оригиналу
        cur.execute(
            sql.SQL("""
                SELECT pg_terminate_backend(pg_stat_activity.pid)
                FROM pg_stat_activity
                WHERE pg_stat_activity.datname = {}
                  AND pid <> pg_backend_pid()
            """).format(sql.Literal(original_db))
        )

        # 1a. Все соединения в нашем пуле к этой БД теперь мертвы (мы их сами и убили).
        # Пул о факте ничего не знает — следующий get_connection() вернёт мёртвый коннект
        # и упадёт с OperationalError. Сбрасываем пул, чтобы он пересоздался лениво.
        orig_key = _pool_key(target_conf)
        with _pool_lock:
            dead_pool = _pool_cache.pop(orig_key, None)
            if dead_pool is not None:
                try:
                    dead_pool.closeall()
                except Exception:
                    pass

        # 2. Клонируем БД (DDL не поддерживает параметры — используем sql.Identifier после валидации)
        cur.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(temp_db)))
        cur.execute(
            sql.SQL("CREATE DATABASE {} WITH TEMPLATE {}").format(
                sql.Identifier(temp_db), sql.Identifier(original_db)
            )
        )
        
        # 3. Подменяем конфиг на временный (копию словаря, чтобы не испортить оригинал!)
        temp_config = target_conf.copy()
        temp_config['dbname'] = temp_db
        
        # 4. Обезличиваем КОПИЮ (передаем временный конфиг!)
        print(f"🧹 Обезличиваем копию...")
        if not findings:
            print("⚠️ Находок нет, дамп будет оригинальным.")
        else:
            # Важно: передаем temp_config, чтобы маскировать КОПИЮ, а не оригинал
            count = mask_data(findings, mode=mode, db_config=temp_config)
            # Примечание: если mask_data вернет 0 ошибок, считаем успехом
        
        # 5. Делаем pg_dump
        env = os.environ.copy()
        env['PGPASSWORD'] = target_conf['password']
        
        cmd = [
            'pg_dump',
            '-h', target_conf['host'],
            '-p', str(target_conf['port']),
            '-U', target_conf['user'],
            '--exclude-table-data=pii_guard.audit_log',
            '-f', dump_file,
            temp_db
        ]
        
        subprocess.run(cmd, env=env, check=True)
        print(f"💾 Дамп готов: {dump_file}")

        try:
            log_conn = psycopg2.connect(**target_conf)
            _pg_sec_event(log_conn,
                'DUMP', f'Безопасный дамп {original_db} создан ({dump_file})')
            log_conn.close()
        except Exception as e:
            print(f"Dump security event error: {e}")

        return dump_file

    except Exception as e:
        print(f"❌ Ошибка дампа: {e}")
        return None
        
    finally:
        # Уборка
        try:
            cur.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(temp_db)))
        except Exception as e:
            print(f"Cleanup error (temp db): {e}")
        cur.close()
        conn.close()

# --- ОТЧЕТЫ (PDF) ---

class PDFReport(FPDF):
    def header(self):
        try:
            self.add_font('DejaVu', '', '/app/DejaVuSans.ttf')
            self.set_font('DejaVu', '', 10)
        except:
            self.set_font('Helvetica', '', 10)
        self.cell(0, 10, 'Postgres PII Guard - Security Scan Report', align='R')
        self.ln(15)
    
    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', align='C')

def create_pdf_report(findings):
    pdf = PDFReport()
    try: pdf.add_font('DejaVu', '', '/app/DejaVuSans.ttf')
    except: pass
    
    pdf.add_page()
    try: pdf.set_font('DejaVu', '', 16)
    except: pdf.set_font('Helvetica', 'B', 16)
        
    pdf.cell(0, 10, 'Отчет о безопасности базы данных', new_x="LMARGIN", new_y="NEXT", align='C')
    pdf.ln(10)
    
    # Метаданные
    pdf.set_font_size(12)
    now = datetime.datetime.now().strftime("%d.%m.%Y %H:%M")
    pdf.cell(0, 10, f'Дата сканирования: {now}', new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 10, f'Всего найдено угроз: {len(findings)}', new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)
    
    # Таблица
    pdf.set_fill_color(200, 220, 255)
    headers = [("ID", 15), ("Тип", 50), ("Таблица", 40), ("Значение", 85)]
    for title, width in headers:
        pdf.cell(width, 10, title, border=1, fill=True)
    pdf.ln()
    
    pdf.set_font_size(10)
    for item in findings[:100]:
        row_id = str(item.get('id', ''))
        row_type = str(item.get('type', ''))
        row_table = str(item.get('table', ''))
        row_val = str(item.get('value', ''))[:40]

        pdf.cell(15, 10, row_id, border=1)
        pdf.cell(50, 10, row_type, border=1)
        pdf.cell(40, 10, row_table, border=1)
        pdf.cell(85, 10, row_val, border=1)
        pdf.ln()
        
    return bytes(pdf.output())

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ (ДЛЯ EXPLORER И ЛОГОВ) ---

def get_db_schema_info(db_config=None):
    """
    Возвращает:
    1. tables_info: Словарь { 'table_name': 'pk_column_name' }
    2. rels: Список связей [('source_table', 'target_table')]
    """
    conn = get_connection(db_config)
    if isinstance(conn, str): return {}, []
    
    cur = conn.cursor()
    try:
        # 1. Получаем список таблиц и их Primary Keys
        # Используем LEFT JOIN, чтобы найти таблицы даже без PK
        cur.execute("""
            SELECT t.table_name, kcu.column_name
            FROM information_schema.tables t
            LEFT JOIN information_schema.table_constraints tc 
                ON t.table_name = tc.table_name 
                AND tc.constraint_type = 'PRIMARY KEY'
                AND tc.table_schema = 'public'
            LEFT JOIN information_schema.key_column_usage kcu 
                ON tc.constraint_name = kcu.constraint_name
                AND tc.table_schema = kcu.table_schema
            WHERE t.table_schema = 'public'
            ORDER BY t.table_name;
        """)
        rows = cur.fetchall()
        
        # Собираем словарь: {'users': 'id', 'logs': 'no_pk'}
        tables_info = {}
        for table, pk in rows:
            # Если PK составной, он может прийти несколькими строками, 
            # но для упрощения берем первый или перезаписываем.
            if table not in tables_info:
                tables_info[table] = pk if pk else ""
            elif pk:
                # Если составной ключ, дописываем через запятую
                tables_info[table] += f", {pk}"

        # 2. Получаем связи (Foreign Keys) - без изменений
        cur.execute("""
            SELECT tc.table_name, ccu.table_name
            FROM information_schema.table_constraints AS tc
            JOIN information_schema.key_column_usage AS kcu ON tc.constraint_name = kcu.constraint_name
            JOIN information_schema.constraint_column_usage AS ccu ON ccu.constraint_name = tc.constraint_name
            WHERE constraint_type = 'FOREIGN KEY' AND tc.table_schema='public';
        """)
        rels = cur.fetchall()
        
        return tables_info, rels
        
    except Exception as e:
        print(f"Schema Error: {e}")
        return {}, []
    finally:
        cur.close()
        close_connection(conn, db_config)

def get_table_statistics(table_name, db_config=None):
    conn = get_connection(db_config)
    if isinstance(conn, str): return {'rows': 0, 'size': '0', 'columns': []}
    cur = conn.cursor()
    stats = {}
    try:
        cur.execute(sql.SQL("SELECT COUNT(*) FROM {}").format(sql.Identifier(table_name)))
        stats['rows'] = cur.fetchone()[0]
        cur.execute(
            sql.SQL("SELECT pg_size_pretty(pg_total_relation_size({}::regclass))").format(sql.Literal(table_name))
        )
        stats['size'] = cur.fetchone()[0]
        cur.execute(
            "SELECT column_name, data_type, is_nullable FROM information_schema.columns "
            "WHERE table_schema = 'public' AND table_name = %s ORDER BY ordinal_position",
            (table_name,)
        )
        stats['columns'] = cur.fetchall()
    except Exception as e:
        print(f"Statistics error for {table_name}: {e}")
        stats = {'rows': 0, 'size': 'err', 'columns': []}
    cur.close()
    close_connection(conn, db_config)
    return stats

def get_table_sample(table_name, limit=5, db_config=None):
    conn = get_connection(db_config)
    if isinstance(conn, str): return []
    cur = conn.cursor()
    try:
        cur.execute(sql.SQL("SELECT * FROM {} LIMIT 0").format(sql.Identifier(table_name)))
        col_names = [desc[0] for desc in cur.description]
        cur.execute(sql.SQL("SELECT * FROM {} LIMIT %s").format(sql.Identifier(table_name)), (limit,))
        rows = cur.fetchall()
        sample = [dict(zip(col_names, row)) for row in rows]
        return sample
    except Exception as e:
        print(f"Sample error for {table_name}: {e}")
        return []
    finally:
        cur.close()
        close_connection(conn, db_config)

def get_db_schema_details(db_config=None):
    """Детальная инфа для вкладки Data Governance"""
    conn = get_connection(db_config) # <--- db_config
    if isinstance(conn, str): return []
    cur = conn.cursor()
    cur.execute("""
        SELECT table_name, column_name, data_type 
        FROM information_schema.columns 
        WHERE table_schema = 'public'
        ORDER BY table_name, column_name
    """)
    rows = cur.fetchall()
    cur.close()
    close_connection(conn, db_config)
    return rows

# SQLite аудит (для локального лога приложения)
AUDIT_DB = "audit_log.db"

def init_audit_db():
    conn = sqlite3.connect(AUDIT_DB)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            action_type TEXT,
            target_db TEXT,
            details TEXT
        )
    """)
    conn.commit()
    conn.close()

def log_event(action_type, target_db, details):
    init_audit_db()
    conn = sqlite3.connect(AUDIT_DB)
    cur = conn.cursor()
    cur.execute("INSERT INTO audit_logs (action_type, target_db, details) VALUES (?, ?, ?)",
                (action_type, target_db, details))
    conn.commit()
    conn.close()

def get_audit_logs():
    init_audit_db()
    conn = sqlite3.connect(AUDIT_DB)
    cur = conn.cursor()
    cur.execute("SELECT timestamp, action_type, target_db, details FROM audit_logs ORDER BY id DESC LIMIT 50")
    rows = cur.fetchall()
    conn.close()
    return rows


# ── АУТЕНТИФИКАЦИЯ И RBAC (Этап 2) ──────────────────────────

def init_auth_db(db_config=None):
    """Создаёт pii_guard.users и дефолтного admin (если таблица пустая)."""
    conn = get_connection(db_config)
    if isinstance(conn, str):
        print(f"Auth DB init error: {conn}")
        return
    cur = conn.cursor()
    try:
        cur.execute("CREATE SCHEMA IF NOT EXISTS pii_guard;")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS pii_guard.users (
                user_id    SERIAL PRIMARY KEY,
                username   TEXT UNIQUE NOT NULL,
                pass_hash  TEXT NOT NULL,
                role       TEXT NOT NULL DEFAULT 'viewer'
                               CHECK (role IN ('admin', 'analyst', 'viewer')),
                created_at TIMESTAMPTZ DEFAULT now(),
                is_active  BOOLEAN DEFAULT TRUE
            )
        """)
        cur.execute("SELECT COUNT(*) FROM pii_guard.users")
        if cur.fetchone()[0] == 0:
            cur.execute(
                "INSERT INTO pii_guard.users (username, pass_hash, role) VALUES (%s, %s, 'admin')",
                ('admin', generate_password_hash('admin123'))
            )
            print("✅ Создан дефолтный пользователь: admin / admin123")
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"Auth DB init error: {e}")
    finally:
        cur.close()
        close_connection(conn, db_config)


class AuthBackendError(Exception):
    """Поднимается, когда verify_user не смог дойти до БД — отличается от
    неверного пароля. Чтобы аудит не забивался ложными LOGIN_FAILED, когда на
    самом деле БД легла."""


def verify_user(username: str, password: str, db_config=None):
    """Проверяет логин/пароль.
    Возвращает (user_id, role) при успехе; None — если такой пары нет.
    Бросает AuthBackendError, если до БД не удалось дойти."""
    conn = get_connection(db_config)
    if isinstance(conn, str):
        raise AuthBackendError(conn)
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT user_id, pass_hash, role FROM pii_guard.users "
            "WHERE username = %s AND is_active = TRUE",
            (username,)
        )
        row = cur.fetchone()
        if row and check_password_hash(row[1], password):
            return (row[0], row[2])
        return None
    except Exception as e:
        # Чтобы соединение не вернулось в пул с aborted-tx.
        try: conn.rollback()
        except Exception: pass
        print(f"verify_user error: {e}")
        raise AuthBackendError(str(e))
    finally:
        cur.close()
        close_connection(conn, db_config)


def create_user(username: str, password: str, role: str = 'viewer', db_config=None) -> bool:
    """Создаёт нового пользователя. Возвращает True при успехе."""
    if role not in ('admin', 'analyst', 'viewer'):
        return False
    conn = get_connection(db_config)
    if isinstance(conn, str):
        return False
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO pii_guard.users (username, pass_hash, role) VALUES (%s, %s, %s)",
            (username, generate_password_hash(password), role)
        )
        _pg_sec_event(conn, 'USER_CREATED',
                      f'Создан пользователь {username} с ролью {role}')
        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        print(f"create_user error: {e}")
        return False
    finally:
        cur.close()
        close_connection(conn, db_config)


def list_users(db_config=None):
    """Возвращает список пользователей (без хэшей)."""
    conn = get_connection(db_config)
    if isinstance(conn, str):
        return []
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT user_id, username, role, created_at, is_active "
            "FROM pii_guard.users ORDER BY user_id"
        )
        return cur.fetchall()
    except Exception as e:
        print(f"list_users error: {e}")
        return []
    finally:
        cur.close()
        close_connection(conn, db_config)


def delete_user(user_id: int, db_config=None) -> bool:
    """Мягкое удаление пользователя (is_active = FALSE).
    Возвращает False, если это последний активный admin — иначе система
    осталась бы без управления."""
    conn = get_connection(db_config)
    if isinstance(conn, str):
        return False
    cur = conn.cursor()
    try:
        # Проверяем: пытаемся ли мы выключить последнего активного admin.
        # SELECT ... FOR UPDATE удерживает строку до commit, чтобы два
        # одновременных DELETE двух разных админов не обошли проверку.
        cur.execute(
            "SELECT role FROM pii_guard.users "
            "WHERE user_id = %s AND is_active = TRUE FOR UPDATE",
            (user_id,)
        )
        target = cur.fetchone()
        if not target:
            conn.rollback()
            return False
        if target[0] == 'admin':
            cur.execute(
                "SELECT COUNT(*) FROM pii_guard.users "
                "WHERE role = 'admin' AND is_active = TRUE"
            )
            (active_admins,) = cur.fetchone()
            if active_admins <= 1:
                conn.rollback()
                print("delete_user: refused — last active admin")
                return False

        cur.execute(
            "UPDATE pii_guard.users SET is_active = FALSE "
            "WHERE user_id = %s RETURNING username",
            (user_id,)
        )
        row = cur.fetchone()
        if row:
            _pg_sec_event(conn, 'USER_DELETED',
                          f'Деактивирован пользователь {row[0]}')
        conn.commit()
        return bool(row)
    except Exception as e:
        conn.rollback()
        print(f"delete_user error: {e}")
        return False
    finally:
        cur.close()
        close_connection(conn, db_config)


def get_security_stats(db_config=None) -> dict:
    """Агрегаты по событиям безопасности за последние 24 часа."""
    conn = get_connection(db_config)
    if isinstance(conn, str):
        return {}
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT
                COUNT(*)                                                      AS total,
                COUNT(*) FILTER (WHERE operation = 'LOGIN_FAILED')            AS login_failed,
                COUNT(*) FILTER (WHERE operation IN ('MASS_MASKING','MASS_FAKER')) AS masking,
                COUNT(*) FILTER (WHERE operation = 'SCAN')                    AS scans
            FROM pii_guard.audit_log
            WHERE event_class = 'SECURITY'
              AND event_time >= now() - INTERVAL '24 hours'
        """)
        row = cur.fetchone()
        if not row:
            return {'total': 0, 'login_failed': 0, 'masking': 0, 'scans': 0}
        return {
            'total':        row[0],
            'login_failed': row[1],
            'masking':      row[2],
            'scans':        row[3],
        }
    except Exception as e:
        print(f"get_security_stats error: {e}")
        return {}
    finally:
        cur.close()
        close_connection(conn, db_config)


def _parse_date_filter(raw):
    """Принимает строку из UI (YYYY-MM-DD или ISO timestamp) и возвращает
    datetime либо None. На мусоре — None, чтобы не пробрасывать его в SQL и
    не получать aborted-tx."""
    if not raw:
        return None
    raw = str(raw).strip()
    if not raw:
        return None
    # Поддерживаем YYYY-MM-DD и полный ISO. fromisoformat в py3.10 не любит 'Z',
    # обрезаем при необходимости.
    try:
        return datetime.datetime.fromisoformat(raw.replace('Z', '+00:00'))
    except (ValueError, TypeError):
        return None


def get_security_events(operation=None, db_user=None,
                        date_from=None, date_to=None,
                        limit=50, offset=0, db_config=None) -> list:
    """
    События безопасности из pii_guard.audit_log (event_class = 'SECURITY').
    Поддерживает фильтрацию по операции, пользователю и диапазону дат.
    """
    conn = get_connection(db_config)
    if isinstance(conn, str):
        return []
    cur = conn.cursor()
    try:
        conditions = ["event_class = 'SECURITY'"]
        params = []
        if operation:
            conditions.append("operation = %s")
            params.append(operation)
        if db_user:
            conditions.append("(db_user ILIKE %s OR app_user ILIKE %s)")
            params.extend([f'%{db_user}%', f'%{db_user}%'])
        # Битые даты раньше прокидывались в PG, ронялись и оставляли соединение
        # в aborted-tx; теперь невалидные значения просто игнорируются.
        df = _parse_date_filter(date_from)
        if df is not None:
            conditions.append("event_time >= %s")
            params.append(df)
        dt = _parse_date_filter(date_to)
        if dt is not None:
            conditions.append("event_time <= %s")
            params.append(dt)

        where = " AND ".join(conditions)
        params.extend([limit, offset])
        cur.execute(f"""
            SELECT event_id, event_time, db_user, app_user, client_ip,
                   operation, details, row_hash
            FROM pii_guard.audit_log
            WHERE {where}
            ORDER BY event_time DESC
            LIMIT %s OFFSET %s
        """, params)
        return cur.fetchall()
    except Exception as e:
        # Обязательно rollback, иначе следующий пользователь пула получит
        # aborted-tx и весь дашборд встанет.
        try: conn.rollback()
        except Exception: pass
        print(f"get_security_events error: {e}")
        return []
    finally:
        cur.close()
        close_connection(conn, db_config)


def verify_audit_chain(db_config=None) -> dict:
    """Запускает verify_audit_chain() в БД. Возвращает словарь с результатом."""
    conn = get_connection(db_config)
    if isinstance(conn, str):
        return {'ok': False, 'message': f'Нет соединения: {conn}'}
    cur = conn.cursor()
    try:
        cur.execute("SELECT ok, broken_event_id, message FROM pii_guard.verify_audit_chain()")
        row = cur.fetchone()
        if row:
            return {'ok': row[0], 'broken_event_id': row[1], 'message': row[2]}
        return {'ok': False, 'message': 'Функция не вернула результат'}
    except Exception as e:
        return {'ok': False, 'message': str(e)}
    finally:
        cur.close()
        close_connection(conn, db_config)


def log_auth_event(event: str, details: str = None, db_config=None):
    """Пишет событие аутентификации в pii_guard.audit_log (ENV-база)."""
    conn = get_connection(db_config)
    if isinstance(conn, str):
        return
    try:
        _pg_sec_event(conn, event, details)
    finally:
        close_connection(conn, db_config)