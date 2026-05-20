FROM python:3.10-slim-bookworm

WORKDIR /app

RUN apt-get update && apt-get install -y \
    graphviz \
    fonts-dejavu \
    postgresql-client \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN ln -s /usr/share/fonts/truetype/dejavu/DejaVuSans.ttf /app/DejaVuSans.ttf

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

# /login доступен без сессии и всегда возвращает 200 — годится для healthcheck.
# Корень редиректит на /scan, /scan требует логина и отдаёт 302, что для --fail означает успех (3xx).
HEALTHCHECK --interval=15s --timeout=5s --retries=4 \
  CMD curl --fail http://localhost:5000/login || exit 1

# По умолчанию запускаем под gunicorn — Flask dev server не годится для проды
# (single-threaded, без graceful reload, утечки трассбэков при дебаг-ошибках).
# Переменная APP_RUNNER=flask переключает обратно на app.run() для отладки.
CMD ["sh", "-c", "python seed_data_relational.py && if [ \"$APP_RUNNER\" = flask ]; then python app.py; else gunicorn --workers ${GUNICORN_WORKERS:-2} --bind 0.0.0.0:5000 --access-logfile - --error-logfile - app:app; fi"]
