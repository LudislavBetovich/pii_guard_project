-- ============================================================
--  PII GUARD — подсистема триггерного аудита событий безопасности
--  Этап 1: контекст сессии, защита от подделки (hash-chain),
--           без утечки PII, аудит событий безопасности
-- ============================================================

-- 1. Схема безопасности
CREATE SCHEMA IF NOT EXISTS pii_guard;

-- 2. Журнал аудита (единый для триггеров и событий безопасности)
CREATE TABLE IF NOT EXISTS pii_guard.audit_log (
    event_id     BIGSERIAL PRIMARY KEY,
    event_time   TIMESTAMPTZ DEFAULT now(),
    -- контекст сессии (1.2)
    db_user      TEXT DEFAULT current_user,   -- роль PostgreSQL
    session_user_name TEXT,                    -- session_user (исходный логин)
    app_user     TEXT,                         -- логин из приложения (GUC pii_guard.app_user)
    client_ip    TEXT,                         -- inet_client_addr()
    app_name     TEXT,                         -- application_name
    txid         BIGINT,                       -- идентификатор транзакции
    -- что произошло
    event_class  TEXT NOT NULL DEFAULT 'DATA', -- DATA | SECURITY
    table_name   TEXT,
    operation    TEXT,
    changed_cols TEXT,                          -- список изменённых колонок (без значений!)
    old_hash     TEXT,                          -- sha256 от ROW(OLD.*) — факт без утечки PII
    new_hash     TEXT,                          -- sha256 от ROW(NEW.*)
    details      TEXT,                          -- человекочитаемое описание события безопасности
    -- защита целостности (1.4)
    prev_hash    TEXT,
    row_hash     TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_table ON pii_guard.audit_log(table_name);
CREATE INDEX IF NOT EXISTS idx_audit_time  ON pii_guard.audit_log(event_time DESC);
CREATE INDEX IF NOT EXISTS idx_audit_op    ON pii_guard.audit_log(operation);
CREATE INDEX IF NOT EXISTS idx_audit_class ON pii_guard.audit_log(event_class);

-- ------------------------------------------------------------
-- 2a. Миграция со старой схемы (если таблица уже существовала)
-- ------------------------------------------------------------
DO $mig$
BEGIN
    -- старые поля old_data/new_data заменены на хэши — добавляем новые колонки
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema='pii_guard' AND table_name='audit_log'
                     AND column_name='row_hash') THEN
        ALTER TABLE pii_guard.audit_log
            ADD COLUMN IF NOT EXISTS session_user_name TEXT,
            ADD COLUMN IF NOT EXISTS app_user     TEXT,
            ADD COLUMN IF NOT EXISTS client_ip    TEXT,
            ADD COLUMN IF NOT EXISTS app_name     TEXT,
            ADD COLUMN IF NOT EXISTS txid         BIGINT,
            ADD COLUMN IF NOT EXISTS event_class  TEXT DEFAULT 'DATA',
            ADD COLUMN IF NOT EXISTS changed_cols TEXT,
            ADD COLUMN IF NOT EXISTS old_hash     TEXT,
            ADD COLUMN IF NOT EXISTS new_hash     TEXT,
            ADD COLUMN IF NOT EXISTS details      TEXT,
            ADD COLUMN IF NOT EXISTS prev_hash    TEXT,
            ADD COLUMN IF NOT EXISTS row_hash     TEXT;
    END IF;
END $mig$;

-- ------------------------------------------------------------
-- 3. Вспомогательная функция: запись в журнал с хэш-цепочкой (1.4)
--    Хэш-цепочка считается сервером в BEFORE INSERT-триггере, не
--    клиентом — даже прямой INSERT не сможет подделать chain. Этот
--    хелпер только формирует контекст сессии и открывает "окно"
--    через GUC pii_guard._append_in_progress; триггер проверит,
--    что INSERT идёт именно через нас.
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION pii_guard._append_log(
    p_event_class  TEXT,
    p_table_name   TEXT,
    p_operation    TEXT,
    p_changed_cols TEXT,
    p_old_hash     TEXT,
    p_new_hash     TEXT,
    p_details      TEXT
) RETURNS void AS $$
DECLARE
    v_app    TEXT;
    v_ip     TEXT;
    v_appnm  TEXT;
BEGIN
    -- открываем "окно" записи только для текущей транзакции (is_local = true)
    PERFORM set_config('pii_guard._append_in_progress', 'on', true);

    -- контекст сессии (мягко: GUC может быть не задан)
    BEGIN  v_app := current_setting('pii_guard.app_user', true);  EXCEPTION WHEN OTHERS THEN v_app := NULL; END;
    v_ip    := COALESCE(host(inet_client_addr()), 'local');
    v_appnm := current_setting('application_name', true);

    -- prev_hash / row_hash заполнит BEFORE INSERT триггер.
    INSERT INTO pii_guard.audit_log (
        event_time,
        db_user, session_user_name, app_user, client_ip, app_name, txid,
        event_class, table_name, operation, changed_cols,
        old_hash, new_hash, details
    ) VALUES (
        clock_timestamp(),
        current_user, session_user, v_app, v_ip, v_appnm, txid_current(),
        p_event_class, p_table_name, p_operation, p_changed_cols,
        p_old_hash, p_new_hash, p_details
    );

    -- закрываем "окно", чтобы случайный последующий INSERT в той же транзакции
    -- (например, в триггере пользовательской таблицы) не прошёл мимо проверки.
    PERFORM set_config('pii_guard._append_in_progress', 'off', true);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- pgcrypto нужен для digest(); ставим если есть права
DO $ext$
BEGIN
    CREATE EXTENSION IF NOT EXISTS pgcrypto;
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'pgcrypto недоступно — хэши будут md5-fallback';
END $ext$;

-- ------------------------------------------------------------
-- 3a. Совместимый digest: если pgcrypto не встал — используем md5
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION pii_guard._sha(t TEXT) RETURNS TEXT AS $$
BEGIN
    RETURN encode(digest(t, 'sha256'), 'hex');
EXCEPTION WHEN undefined_function THEN
    RETURN md5(t);
END;
$$ LANGUAGE plpgsql;

-- ------------------------------------------------------------
-- 4. Триггерная функция аудита данных (1.1 + 1.3)
--    INSERT / UPDATE / DELETE. PII НЕ пишется — только хэши и
--    список изменённых колонок.
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION pii_guard.log_changes()
RETURNS TRIGGER AS $$
DECLARE
    v_old   TEXT := NULL;
    v_new   TEXT := NULL;
    v_cols  TEXT := NULL;
BEGIN
    IF (TG_OP = 'DELETE') THEN
        v_old := pii_guard._sha(ROW(OLD.*)::text);
    ELSIF (TG_OP = 'INSERT') THEN
        v_new := pii_guard._sha(ROW(NEW.*)::text);
    ELSE  -- UPDATE
        v_old := pii_guard._sha(ROW(OLD.*)::text);
        v_new := pii_guard._sha(ROW(NEW.*)::text);
        -- какие колонки реально изменились (имена, не значения)
        SELECT string_agg(key, ', ')
          INTO v_cols
        FROM jsonb_each_text(to_jsonb(NEW)) n
        JOIN jsonb_each_text(to_jsonb(OLD)) o USING (key)
        WHERE n.value IS DISTINCT FROM o.value;
    END IF;

    PERFORM pii_guard._append_log(
        'DATA', TG_TABLE_NAME, TG_OP, v_cols, v_old, v_new, NULL
    );
    RETURN NULL;  -- AFTER-триггер
END;
$$ LANGUAGE plpgsql;

-- ------------------------------------------------------------
-- 4a. Триггер на изменение правил разметки (событие безопасности)
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION pii_guard.log_settings_change()
RETURNS TRIGGER AS $$
DECLARE
    v_detail TEXT;
BEGIN
    IF (TG_OP = 'DELETE') THEN
        v_detail := format('Удалено правило %s.%s', OLD.table_name, OLD.column_name);
    ELSE
        v_detail := format('Правило %s.%s -> статус=%s, тип=%s',
                           NEW.table_name, NEW.column_name, NEW.status,
                           COALESCE(NEW.pii_type, '-'));
    END IF;
    PERFORM pii_guard._append_log(
        'SECURITY', 'column_settings', 'GOVERNANCE_CHANGE', NULL, NULL, NULL, v_detail
    );
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- ------------------------------------------------------------
-- 5. Процедура: включить аудит на таблице (1.1: + INSERT)
--
-- Принимает имя таблицы И опционально схему. Раньше использовалось %I без
-- квалификации схемы — если в разных схемах есть одноимённые таблицы,
-- триггер цеплялся на первую попавшуюся по search_path. Теперь явно.
-- ------------------------------------------------------------
CREATE OR REPLACE PROCEDURE pii_guard.enable_audit(
    target_table  TEXT,
    target_schema TEXT DEFAULT 'public'
)
LANGUAGE plpgsql AS $$
BEGIN
    EXECUTE format('DROP TRIGGER IF EXISTS trg_audit_changes ON %I.%I',
                   target_schema, target_table);
    EXECUTE format('
        CREATE TRIGGER trg_audit_changes
        AFTER INSERT OR UPDATE OR DELETE ON %I.%I
        FOR EACH ROW
        EXECUTE FUNCTION pii_guard.log_changes()',
        target_schema, target_table
    );
END;
$$;

-- 5a. Включить аудит изменений разметки
CREATE OR REPLACE PROCEDURE pii_guard.enable_settings_audit()
LANGUAGE plpgsql AS $$
BEGIN
    DROP TRIGGER IF EXISTS trg_settings_audit ON pii_guard.column_settings;
    CREATE TRIGGER trg_settings_audit
        AFTER INSERT OR UPDATE OR DELETE ON pii_guard.column_settings
        FOR EACH ROW EXECUTE FUNCTION pii_guard.log_settings_change();
EXCEPTION WHEN undefined_table THEN
    RAISE NOTICE 'column_settings ещё не создана — аудит разметки будет включён позже';
END;
$$;

-- ------------------------------------------------------------
-- 6. Процедура: быстрое маскирование (SQL-way) + событие безопасности
--
-- Принимает имя таблицы И опционально схему. Перед UPDATE проверяет, что
-- колонка существует и относится к строковому типу — раньше попытка
-- замаскировать integer/timestamp в строку '****' валила transaction-level
-- ошибкой и откатывала запись в аудит.
-- ------------------------------------------------------------
CREATE OR REPLACE PROCEDURE pii_guard.fast_mask(
    t_name  TEXT,
    c_name  TEXT,
    schema_ TEXT DEFAULT 'public'
)
LANGUAGE plpgsql AS $$
DECLARE
    v_cnt    BIGINT;
    v_type   TEXT;
BEGIN
    SELECT data_type INTO v_type
    FROM information_schema.columns
    WHERE table_schema = schema_ AND table_name = t_name AND column_name = c_name;

    IF v_type IS NULL THEN
        RAISE NOTICE 'fast_mask: колонка %.%.% не найдена', schema_, t_name, c_name;
        RETURN;
    END IF;
    IF v_type NOT IN ('text', 'character varying', 'character', 'citext') THEN
        RAISE NOTICE 'fast_mask: колонка %.%.% имеет тип % — маскирование пропущено',
                     schema_, t_name, c_name, v_type;
        RETURN;
    END IF;

    EXECUTE format('UPDATE %I.%I SET %I = ''****'' WHERE %I IS NOT NULL',
                   schema_, t_name, c_name, c_name);
    GET DIAGNOSTICS v_cnt = ROW_COUNT;

    PERFORM pii_guard._append_log(
        'SECURITY', t_name, 'MASS_MASKING', c_name, NULL, NULL,
        format('Колонка %s.%s.%s обезличена (%s строк)', schema_, t_name, c_name, v_cnt)
    );
END;
$$;

-- ------------------------------------------------------------
-- 7. API событий безопасности приложения (1.5)
--    Вызывается из backend.py: SCAN / MASK / DUMP / AUTH ...
-- ------------------------------------------------------------
CREATE OR REPLACE PROCEDURE pii_guard.log_security_event(
    p_event   TEXT,
    p_details TEXT DEFAULT NULL
)
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pii_guard._append_log(
        'SECURITY', NULL, p_event, NULL, NULL, NULL, p_details
    );
END;
$$;

-- ------------------------------------------------------------
-- 8. Защита журнала от подделки (1.4)
--    8a. Запрет UPDATE/DELETE/TRUNCATE на уровне триггера
--        (надёжнее REVOKE: ловит даже владельца таблицы).
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION pii_guard.block_log_tamper()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Журнал аудита защищён: операция % запрещена', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_immutable ON pii_guard.audit_log;
CREATE TRIGGER trg_audit_immutable
    BEFORE UPDATE OR DELETE OR TRUNCATE ON pii_guard.audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION pii_guard.block_log_tamper();

-- 8a-bis. BEFORE INSERT: сервер сам считает prev_hash/row_hash, клиент их подделать
--         не может. Под xact-advisory-lock — конкурентные вставки не разорвут цепочку.
--         GUC pii_guard._append_in_progress = 'on' выставляется только из _append_log,
--         так что прямой INSERT (даже с правильными хэшами) будет отвергнут.
CREATE OR REPLACE FUNCTION pii_guard.audit_log_before_insert()
RETURNS TRIGGER AS $$
DECLARE
    v_prev     TEXT;
    v_ts_str   TEXT;
    v_payload  TEXT;
BEGIN
    IF COALESCE(current_setting('pii_guard._append_in_progress', true), 'off') <> 'on' THEN
        RAISE EXCEPTION 'Журнал аудита защищён: прямой INSERT запрещён, используйте pii_guard._append_log()';
    END IF;

    -- сериализация: на уровне транзакции, иначе параллельные _append_log
    -- прочитают один и тот же prev_hash и цепочка разветвится.
    PERFORM pg_advisory_xact_lock(hashtext('pii_guard.audit_log'));

    SELECT row_hash INTO v_prev
    FROM pii_guard.audit_log
    ORDER BY event_id DESC
    LIMIT 1;
    v_prev := COALESCE(v_prev, 'GENESIS');

    -- event_time форматируем как UTC-строку фиксированного формата,
    -- иначе verify в другой TZ/DateStyle получит "подделку" на ровном месте.
    v_ts_str := to_char(NEW.event_time AT TIME ZONE 'UTC',
                        'YYYY-MM-DD HH24:MI:SS.US');

    v_payload := concat_ws('|',
        v_prev,
        NEW.event_class, NEW.table_name, NEW.operation,
        NEW.changed_cols, NEW.old_hash, NEW.new_hash, NEW.details,
        NEW.db_user, NEW.session_user_name, NEW.app_user, NEW.client_ip,
        NEW.app_name, NEW.txid::text, v_ts_str);

    NEW.prev_hash := v_prev;
    NEW.row_hash  := pii_guard._sha(v_payload);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_before_insert ON pii_guard.audit_log;
CREATE TRIGGER trg_audit_before_insert
    BEFORE INSERT ON pii_guard.audit_log
    FOR EACH ROW EXECUTE FUNCTION pii_guard.audit_log_before_insert();

-- 8a-ter. Защита от прямой записи: только _append_log (SECURITY DEFINER)
--         легитимно вставляет в audit_log. Для обычных ролей INSERT
--         запрещён даже на уровне привилегий.
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON pii_guard.audit_log FROM PUBLIC;

-- 8b. Проверка целостности хэш-цепочки.
--     Возвращает (ok, broken_event_id, message). Формула payload должна
--     быть БАЙТ-В-БАЙТ той же, что в audit_log_before_insert().
CREATE OR REPLACE FUNCTION pii_guard.verify_audit_chain()
RETURNS TABLE(ok BOOLEAN, broken_event_id BIGINT, message TEXT) AS $$
DECLARE
    r          RECORD;
    v_prev     TEXT := 'GENESIS';
    v_payload  TEXT;
    v_calc     TEXT;
    v_ts_str   TEXT;
BEGIN
    FOR r IN SELECT * FROM pii_guard.audit_log ORDER BY event_id LOOP
        IF r.prev_hash IS DISTINCT FROM v_prev THEN
            ok := FALSE; broken_event_id := r.event_id;
            message := format('Разрыв цепочки на event_id=%s (prev_hash не совпал)', r.event_id);
            RETURN NEXT; RETURN;
        END IF;

        IF r.row_hash IS NULL THEN
            ok := FALSE; broken_event_id := r.event_id;
            message := format('Пустой row_hash на event_id=%s', r.event_id);
            RETURN NEXT; RETURN;
        END IF;

        v_ts_str := to_char(r.event_time AT TIME ZONE 'UTC',
                            'YYYY-MM-DD HH24:MI:SS.US');
        v_payload := concat_ws('|',
            r.prev_hash, r.event_class, r.table_name, r.operation,
            r.changed_cols, r.old_hash, r.new_hash, r.details,
            r.db_user, r.session_user_name, r.app_user, r.client_ip,
            r.app_name, r.txid::text, v_ts_str);
        v_calc := pii_guard._sha(v_payload);

        IF v_calc IS DISTINCT FROM r.row_hash THEN
            ok := FALSE; broken_event_id := r.event_id;
            message := format('Подделка обнаружена на event_id=%s (row_hash не совпал)', r.event_id);
            RETURN NEXT; RETURN;
        END IF;

        v_prev := r.row_hash;
    END LOOP;

    ok := TRUE; broken_event_id := NULL;
    message := 'Цепочка журнала аудита целостна';
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- ============================================================
-- 9. Таблица пользователей приложения (Этап 2 — RBAC)
--    pass_hash хранится как werkzeug pbkdf2:sha256 строка.
--    Начальный admin создаётся из Python при старте приложения.
-- ============================================================
CREATE TABLE IF NOT EXISTS pii_guard.users (
    user_id    SERIAL PRIMARY KEY,
    username   TEXT UNIQUE NOT NULL,
    pass_hash  TEXT NOT NULL,
    role       TEXT NOT NULL DEFAULT 'viewer'
                   CHECK (role IN ('admin', 'analyst', 'viewer')),
    created_at TIMESTAMPTZ DEFAULT now(),
    is_active  BOOLEAN DEFAULT TRUE
);

-- ============================================================
-- 10. Отдельная роль приложения (минимальные привилегии)
--
-- Подключаться к БД суперпользователем — критическая ошибка: суперюзер обходит
-- любые триггеры через ALTER TABLE ... DISABLE TRIGGER ALL, поэтому защита
-- журнала аудита (immutable + BEFORE INSERT chain enforcement) на нём
-- бесполезна. Этот блок создаёт роль pii_guard_app, которая:
--   • НЕ суперюзер, не владелец audit_log, не может отключать триггеры;
--   • может читать/писать данные в public (нужно сканеру и масс-маскированию);
--   • может ВЫЗВАТЬ _append_log() / fast_mask() / verify_audit_chain(), но
--     не может вставлять/обновлять/удалять напрямую в audit_log
--     (см. REVOKE выше + триггер, проверяющий GUC из _append_log).
--
-- Чтобы приложение реально под ней работало, в docker-compose.yml выставите
-- POSTGRES_USER / DB_APP_USER = pii_guard_app и пароль через .env. Этот
-- init_db_logic.sql при этом по-прежнему применять должен суперюзер (admin),
-- потому что только он может выполнять CREATE EXTENSION / CREATE ROLE.
-- ============================================================
DO $role$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pii_guard_app') THEN
        -- Пароль ставится из переменной окружения PG_APP_PASSWORD (см. README).
        -- Фолбэк-значение оставлено, чтобы dev-стенд из коробки не падал —
        -- в проде обязательно ALTER ROLE pii_guard_app PASSWORD '...'.
        EXECUTE format(
            'CREATE ROLE pii_guard_app LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE',
            COALESCE(current_setting('pii_guard.app_password', true), 'change-me-app-pass')
        );
    END IF;
END $role$;

-- Доступ к схемам
GRANT USAGE ON SCHEMA pii_guard TO pii_guard_app;
GRANT USAGE ON SCHEMA public    TO pii_guard_app;

-- В public роль должна уметь SELECT/INSERT/UPDATE/DELETE — для сканера и
-- маскирования сырых таблиц. Без CREATE/ALTER/TRUNCATE.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO pii_guard_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO pii_guard_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO pii_guard_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO pii_guard_app;

-- В pii_guard — только SELECT (для дашбордов) и EXECUTE на функции/процедуры.
-- Прямые INSERT/UPDATE/DELETE в audit_log намеренно НЕ даём: запись идёт
-- исключительно через _append_log (SECURITY DEFINER), который выставляет
-- GUC-флаг для BEFORE INSERT-триггера. Это и есть основная гарантия,
-- что хеш-цепочка останется не подделанной.
GRANT SELECT ON ALL TABLES IN SCHEMA pii_guard TO pii_guard_app;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA pii_guard TO pii_guard_app;
-- Процедуры (PROCEDURE) — отдельная гранта в PG 11+
DO $grant_proc$
BEGIN
    EXECUTE 'GRANT EXECUTE ON ALL PROCEDURES IN SCHEMA pii_guard TO pii_guard_app';
EXCEPTION WHEN OTHERS THEN
    -- PG <11: PROCEDURE'ы не существуют, грант не нужен.
    NULL;
END $grant_proc$;
ALTER DEFAULT PRIVILEGES IN SCHEMA pii_guard
    GRANT EXECUTE ON FUNCTIONS TO pii_guard_app;
-- users — приложение должно уметь логиниться и управлять пользователями
GRANT INSERT, UPDATE ON pii_guard.users TO pii_guard_app;
GRANT USAGE, SELECT ON SEQUENCE pii_guard.users_user_id_seq TO pii_guard_app;
