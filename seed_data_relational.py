"""
PII Guard — Seed-данные для демонстрации на защите диплома.
Моделируемая организация: IT-компания «ТехноПром» (HR + финансы + системные аккаунты).

Покрытие детекторов:
  ✅ Luhn       — номера банковских карт (payroll.card_number)
  ✅ INN12      — ИНН физлица сотрудников (employees.inn)
  ✅ INN10      — ИНН юрлиц (companies.inn)
  ✅ SNILS      — СНИЛС сотрудников (employees.snils)
  RegEx:  ФИО, дата рождения, email, телефон, паспорт, ОГРН, КПП,
          IBAN, хэш пароля (BCrypt / MD5), API-ключ, IPv4
"""

import os
import random
import string
import psycopg2
from faker import Faker
import backend

fake = Faker('ru_RU')
random.seed(42)

DB_CONFIG = {
    "dbname":   os.getenv("POSTGRES_DB",       "testdb"),
    "user":     os.getenv("POSTGRES_USER",     "admin"),
    "password": os.getenv("POSTGRES_PASSWORD", "secret_password"),
    "host":     os.getenv("DB_HOST",           "localhost"),
    "port":     os.getenv("DB_PORT",           "5432"),
}

# ── Генераторы с корректными контрольными суммами ─────────────

def gen_inn12() -> str:
    """ИНН физлица (12 цифр) — правильные контрольные цифры."""
    w1 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
    w2 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
    d = [random.randint(0, 9) for _ in range(10)]
    c1 = sum(w * d[i] for i, w in enumerate(w1)) % 11 % 10
    d.append(c1)
    c2 = sum(w * d[i] for i, w in enumerate(w2)) % 11 % 10
    d.append(c2)
    return ''.join(map(str, d))


def gen_inn10() -> str:
    """ИНН юрлица (10 цифр) — правильная контрольная цифра."""
    weights = [2, 4, 10, 3, 5, 9, 4, 6, 8]
    d = [random.randint(0, 9) for _ in range(9)]
    check = sum(w * d[i] for i, w in enumerate(weights)) % 11 % 10
    return ''.join(map(str, d)) + str(check)


def gen_snils() -> str:
    """СНИЛС (формат NNN-NNN-NNN CC) — правильные контрольные цифры."""
    while True:
        d = [random.randint(0, 9) for _ in range(9)]
        number = int(''.join(map(str, d)))
        if number < 1001998:          # старые номера — пропускаем
            continue
        total = sum((9 - i) * d[i] for i in range(9)) % 101
        if total >= 100:
            total = 0
        p = ''.join(map(str, d))
        return f'{p[:3]}-{p[3:6]}-{p[6:9]} {total:02d}'


def gen_ogrn() -> str:
    """ОГРН (13 цифр) — правильная контрольная цифра."""
    d = str(random.randint(100000000000, 999999999999))   # 12 цифр
    check = int(d) % 11 % 10
    return d + str(check)


def gen_kpp() -> str:
    """КПП (9 цифр, без контрольной суммы)."""
    return (f'{random.randint(100, 999)}'
            f'{random.randint(100, 999)}'
            f'{random.randint(100, 999)}')


def gen_bcrypt_like() -> str:
    """Строка в формате BCrypt — детектируется паттерном Password Hash (BCrypt)."""
    chars = string.ascii_letters + string.digits + './'
    return '$2b$12$' + ''.join(random.choices(chars, k=53))


def gen_md5() -> str:
    """MD5-подобный хэш (32 hex-символа)."""
    return ''.join(random.choices('0123456789abcdef', k=32))


def gen_api_key() -> str:
    """Generic API Key: 40 символов, обязательно верхний + нижний регистр + цифра."""
    pool = string.ascii_uppercase + string.ascii_lowercase + string.digits
    key = (random.choices(string.ascii_uppercase, k=4) +
           random.choices(string.ascii_lowercase, k=4) +
           random.choices(string.digits, k=4) +
           random.choices(pool, k=28))
    random.shuffle(key)
    return ''.join(key)


def gen_ipv4() -> str:
    return (f'{random.randint(10, 192)}.'
            f'{random.randint(0, 255)}.'
            f'{random.randint(0, 255)}.'
            f'{random.randint(1, 254)}')


# ── Схема базы данных ─────────────────────────────────────────

def create_schema(cur):
    print('🏗️  Создаю схему (IT-компания «ТехноПром»)…')

    # Полная очистка: pii_guard пересоздаётся через init_db_security
    cur.execute('DROP SCHEMA IF EXISTS pii_guard CASCADE;')

    for tbl in ('payroll', 'system_accounts', 'employees', 'companies'):
        cur.execute(f'DROP TABLE IF EXISTS {tbl} CASCADE;')

    # Компании (головная + дочерние / клиенты)
    cur.execute("""
        CREATE TABLE companies (
            id           SERIAL PRIMARY KEY,
            company_name TEXT NOT NULL,
            inn          TEXT,   -- ИНН 10 цифр  ← INN10 валидатор
            ogrn         TEXT,   -- ОГРН 13 цифр ← RegEx
            kpp          TEXT    -- КПП 9 цифр   ← RegEx
        );
    """)

    # Сотрудники
    cur.execute("""
        CREATE TABLE employees (
            id         SERIAL PRIMARY KEY,
            company_id INTEGER REFERENCES companies(id),
            full_name  TEXT,    -- ФИО             ← FIO (RU)
            birth_date TEXT,    -- дата рождения   ← Date of Birth
            email      TEXT,    -- email           ← Email
            phone      TEXT,    -- телефон         ← Phone (RU)
            passport   TEXT,    -- серия + номер   ← Passport (RU Internal)
            snils      TEXT,    -- СНИЛС           ← SNILS валидатор
            inn        TEXT     -- ИНН физлица     ← INN12 валидатор
        );
    """)

    # Зарплатная ведомость
    cur.execute("""
        CREATE TABLE payroll (
            id          SERIAL PRIMARY KEY,
            employee_id INTEGER REFERENCES employees(id),
            card_number TEXT,           -- карта  ← Credit Card (Luhn)
            iban        TEXT,           -- IBAN   ← IBAN
            salary      NUMERIC(12, 2)
        );
    """)

    # Системные аккаунты
    cur.execute("""
        CREATE TABLE system_accounts (
            id          SERIAL PRIMARY KEY,
            employee_id INTEGER REFERENCES employees(id),
            login       TEXT,
            password_hash TEXT,  -- BCrypt / MD5  ← Password Hash
            api_key       TEXT,  -- API-ключ      ← Generic API Key
            last_ip       TEXT   -- IP-адрес      ← IPv4 Address
        );
    """)
    print('   ✓ Таблицы созданы.')


# ── Наполнение данными ────────────────────────────────────────

def generate_data(conn, cur):
    print('🎲 Генерирую данные…')

    # --- Компании (10 организаций) ---
    company_ids = []
    company_names = [
        'ТехноПром ООО', 'СофтЛайн АО', 'ДатаБридж ООО', 'КиберСистемс ЗАО',
        'ИнфоТех ООО', 'ПрайматекС АО', 'ДиджиталВэй ООО', 'НетворкПро ЗАО',
        'КлаудСервис ООО', 'АйТи Решения АО',
    ]
    for name in company_names:
        cur.execute(
            'INSERT INTO companies (company_name, inn, ogrn, kpp) VALUES (%s,%s,%s,%s) RETURNING id',
            (name, gen_inn10(), gen_ogrn(), gen_kpp())
        )
        company_ids.append(cur.fetchone()[0])
    print(f'   ✓ Компании: {len(company_ids)}')

    # --- Сотрудники (80 человек) ---
    employee_ids = []
    for _ in range(80):
        dob = fake.date_of_birth(minimum_age=22, maximum_age=62).strftime('%d.%m.%Y')
        passport = (f'{random.randint(1000,9999)} '
                    f'{random.randint(100000,999999)}')
        phone = f'+79{random.randint(100000000,999999999)}'
        cur.execute(
            """INSERT INTO employees
               (company_id, full_name, birth_date, email, phone, passport, snils, inn)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
            (
                random.choice(company_ids),
                fake.name(),
                dob,
                fake.email(),
                phone,
                passport,
                gen_snils(),
                gen_inn12(),
            )
        )
        employee_ids.append(cur.fetchone()[0])
    print(f'   ✓ Сотрудники: {len(employee_ids)}')

    # --- Зарплатная ведомость ---
    for eid in employee_ids:
        cur.execute(
            'INSERT INTO payroll (employee_id, card_number, iban, salary) VALUES (%s,%s,%s,%s)',
            (
                eid,
                fake.credit_card_number(),          # Faker генерирует Luhn-корректные номера
                fake.iban(),
                round(random.uniform(60_000, 350_000), 2),
            )
        )
    print(f'   ✓ Зарплатная ведомость: {len(employee_ids)} записей')

    # --- Системные аккаунты ---
    # 60 с BCrypt-хэшем, 20 с MD5 (для демонстрации разных типов)
    for i, eid in enumerate(employee_ids):
        pwd_hash = gen_bcrypt_like() if i < 60 else gen_md5()
        cur.execute(
            """INSERT INTO system_accounts
               (employee_id, login, password_hash, api_key, last_ip)
               VALUES (%s,%s,%s,%s,%s)""",
            (
                eid,
                fake.user_name(),
                pwd_hash,
                gen_api_key(),
                gen_ipv4(),
            )
        )
    print(f'   ✓ Системные аккаунты: {len(employee_ids)} записей')

    conn.commit()
    print('✅ Данные сохранены.')


# ── Точка входа ───────────────────────────────────────────────

if __name__ == '__main__':
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur  = conn.cursor()
        create_schema(cur)
        generate_data(conn, cur)
        cur.close()
        conn.close()

        print('🛡️  Применяю патч безопасности (триггеры, аудит)…')
        backend.init_db_security(DB_CONFIG)

        print('🔐 Инициализирую auth (пользователи приложения)…')
        backend.init_auth_db(DB_CONFIG)

        print('🎉 Seed завершён. Приложение готово к демонстрации.')
        print('   Логин: admin / admin123')

    except Exception as e:
        print(f'❌ Ошибка seed: {e}')
        raise
