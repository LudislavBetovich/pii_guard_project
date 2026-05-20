# 🛡️ Postgres PII Guard (Enterprise Edition)

[![Python](https://img.shields.io/badge/Python-3.10-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Frontend-Flask%20%2B%20Jinja2-000000?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![PostgreSQL](https://img.shields.io/badge/Database-PostgreSQL%2015-336791?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Docker](https://img.shields.io/badge/Deploy-Docker-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

**Postgres PII Guard** — комплексное DLP-решение (Data Loss Prevention) для обнаружения, классификации и обезличивания персональных данных (PII) в базах данных PostgreSQL.

Инструмент позволяет соблюдать требования **152-ФЗ / GDPR**, безопасно передавать дампы разработчикам и проводить аудит событий безопасности с криптографической защитой от подделки журнала.

---

## ✨ Ключевые возможности

### 🕵️ Умное сканирование (Smart Scan)
*   **Глубокий анализ:** Поиск по RegEx (Паспорта РФ, СНИЛС, ИНН, ОГРН, ОМС, Email, Кредитки, Crypto-кошельки, BCrypt-хэши и др.).
*   **Контекстный фильтр:** Отсеивание технических полей (timestamp, id, uuid) для снижения ложных срабатываний.
*   **Metadata Profiling:** Анализ названий колонок для поиска скрытых угроз (`user_pass`, `card_num`).

### 🏷️ Data Governance
*   **Интерактивная разметка:** UI для ручной классификации колонок.
*   **Режимы:** `AUTO`, `IGNORE`, `FORCE_PII`.
*   **Stateful Config:** Настройки хранятся в схеме `pii_guard` внутри самой БД.

### 🛡️ Обезличивание и Защита
*   **Masking:** Быстрое скрытие данных (`****`) через PL/pgSQL-процедуру `pii_guard.fast_mask`.
*   **Synthetic Data (Faker):** Замена реальных данных на реалистичные фейки.
*   **Safe Dump Export:** Клонирование БД → обезличивание копии → `pg_dump` с исключением audit-таблицы.

### 🔐 Журнал аудита с hash-chain
*   **PostgreSQL-триггеры:** `INSERT/UPDATE/DELETE` на пользовательских таблицах автоматически логируются (хэши строк, без утечки PII).
*   **SHA-256 hash chain:** Каждая запись содержит `prev_hash`/`row_hash`. Подделка/удаление любой строки рвёт цепочку → детектируется `pii_guard.verify_audit_chain()`.
*   **Sealed inserts:** Прямые `INSERT` в `audit_log` отвергаются BEFORE INSERT-триггером; писать может только `_append_log()` (`SECURITY DEFINER`).
*   **Advisory lock:** Параллельные записи в журнал сериализованы → цепочка не ветвится.
*   **UI:** Двухвкладочный журнал (App logs + Database Triggers) + дашборд событий безопасности.

### 👥 RBAC (Role-Based Access Control)
*   **Роли:** `admin` (полный доступ), `analyst` (сканирование + разметка), `viewer` (только просмотр).
*   **Защита от self-lockout:** последний активный admin не может быть деактивирован.
*   **Session fixation defense:** при логине session id перевыпускается.
*   **CSRF:** все POST-формы и JSON-fetch-запросы защищены токеном + `SameSite=Strict` cookie.

### ⚙️ Архитектура
*   **Connection Pooling:** `psycopg2 ThreadedConnectionPool` с self-healing после `pg_terminate_backend`.
*   **Production WSGI:** Gunicorn (2 воркера) с health-эндпоинтом и access-логом в stdout.
*   **Security First:** Все идентификаторы через `psycopg2.sql.Identifier`, CSP-заголовок, `HttpOnly`-сессии.
*   **Audit Logs:** Двухуровневое логирование (приложение + триггеры БД).

---

## 🛠️ Технический стек

| Компонент | Технологии |
|-----------|------------|
| **Backend** | Python 3.10, Flask 3.0, `psycopg2-binary` (Pooling), `Faker`, Werkzeug security |
| **Frontend** | Flask + Jinja2, Bootstrap 5, Chart.js |
| **WSGI** | Gunicorn 21 |
| **Database** | PostgreSQL 15 (Triggers, Stored Procedures, pgcrypto, hash chain) |
| **DevOps** | Docker, Docker Compose, healthcheck |
| **Reporting** | FPDF2 (отчёты с кириллицей) |
| **Viz** | Graphviz (ER-диаграммы) |

---

## 🚀 Быстрый старт

Требуется установленный **Docker** и **Docker Compose**.

1.  **Запуск приложения:**
    ```bash
    docker compose up --build
    ```
    *При первом запуске база автоматически наполнится тестовыми данными (демо-компания «ТехноПром»: 10 компаний, 80 сотрудников, payroll + системные аккаунты — все распространённые PII-типы покрыты.)*

2.  **Доступ к интерфейсу:**
    Откройте в браузере: **http://localhost:5000**

3.  **Учётные данные по умолчанию:**
    * Логин: `admin`
    * Пароль: `admin123`
    * **Смените пароль немедленно после первого входа в любой не-демо среде.**

4.  **Остановка:**
    ```bash
    docker compose down
    ```

---

## 🔒 Production-чеклист

Перед промышленным запуском обязательно выставьте через `.env`:

```env
SECRET_KEY=<openssl rand -hex 32>
POSTGRES_PASSWORD=<сильный пароль>
SESSION_COOKIE_SECURE=1            # если приложение за HTTPS-прокси
DB_APP_USER=pii_guard_app          # минимально-привилегированная роль (не суперюзер)
```

* Замените дефолтный `admin/admin123` сразу после первого входа.
* В Production не используйте суперюзера для приложения: роль `pii_guard_app`
  создаётся в `init_db_logic.sql` с минимально нужными правами и не может
  отключать триггер защиты `audit_log`.
* В `docker-compose.yml` уберите fallback-значения паролей.

---

## 📖 Руководство пользователя

### 1. Вход
Откройте http://localhost:5000 — попадёте на форму логина. Введите учётные данные.

### 2. Подключение к базе данных
Меню → **Подключение**. Для локального стенда — кнопка **«Загрузить из ENV»**, заполнит поля из `docker-compose`. Для облачной БД (Render/AWS) включите галочку **SSL**.

### 3. Разметка данных (Data Governance)
Меню → **Разметка**. Для каждой колонки выберите статус:

| Статус | Описание | Когда использовать |
| :--- | :--- | :--- |
| **AUTO** | Система сама решает (пропускает `id`, `created_at`, `updated_at`). | Большинство полей. |
| **IGNORE** | Полностью исключается из проверки. | Технические, логи, хэши. |
| **FORCE_PII** | Принудительная проверка указанным алгоритмом. | Нестандартные поля (`user_login`, `token`). |

### 4. Сканирование
Меню → **Сканер**.
1.  (Опционально) добавьте свои паттерны в «Свои критерии».
2.  Настройте глубину сканирования (1000–5000 строк).
3.  Нажмите **«Запустить сканирование»** (доступно admin/analyst).
4.  Результаты автоматически откроются в **Результатах**.

### 5. Обезличивание и Экспорт (только admin)

#### 🅰️ Безопасный дамп (рекомендуется)
Клонирует БД → маскирует копию → отдаёт `.sql`-файл с вырезанным `audit_log`. Оригинал не меняется.

#### 🅱️ Danger Zone — изменение оригинала
Необратимо меняет данные в подключённой базе. Требуется галочка-предохранитель.

### 6. Журнал и Безопасность
* **Аудит** — приложенческие логи + триггерный журнал PostgreSQL.
* **Безопасность** — дашборд событий + кнопка **«Проверить»** (запускает `verify_audit_chain` и показывает целостность hash-цепочки).

### 7. Управление пользователями (только admin)
Меню → **Пользователи** — создание, деактивация, матрица прав.

---

## 🔧 Устранение неполадок (FAQ)

| Проблема | Причина | Решение |
| :--- | :--- | :--- |
| `Error creating connection pool` | Неверные данные или требование SSL. | Для облачной БД — включите SSL в форме подключения. |
| Контейнер `unhealthy` | DB не успела стартовать. | Подождите 10–20 сек, `docker compose logs db`. |
| Сканер ничего не нашёл | Сработали стоп-слова. | Выставьте `FORCE_PII` с типом `Generic / Any Content` в Разметке. |
| «Сервис временно недоступен» при логине | БД легла. | `docker compose logs db`, проверьте healthcheck. |
| `Нарушение целостности!` в проверке цепочки | Чьё-то прямое вмешательство в `audit_log` или баг в payload. | Проверьте `event_id` из сообщения; восстановите из бэкапа. |

---

## 🏗️ Структура проекта

*   `app.py` — Flask-роуты, аутентификация, RBAC, CSRF, инициализация при старте.
*   `backend.py` — Сканирование, пул соединений, маскирование, безопасный дамп, аудит-события.
*   `validators.py` — Алгоритмические валидаторы (Luhn для карт, контрольные суммы СНИЛС/ИНН и т.д.).
*   `init_db_logic.sql` — Схема `pii_guard`, hash-chain, триггеры аудита, роль `pii_guard_app`.
*   `seed_data_relational.py` — Генератор демо-данных «ТехноПром».
*   `templates/` — Jinja2-шаблоны (base, login, scan, results, audit, security, governance, admin/users, ...).
*   `static/style.css` — Стили.
*   `Dockerfile`, `docker-compose.yml`, `.dockerignore` — Контейнеризация.

---

**Разработано в рамках дипломного проекта (ВКР, 2026).**
