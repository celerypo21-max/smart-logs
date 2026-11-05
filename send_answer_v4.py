"""
send_answer_v4.py — модуль проекта log-analyzer.
Выгружает события безопасности из Postgres в JSON,
отправляет их GigaChat на анализ и присылает отчёт письмом.
"""
import os
import json
import smtplib
from pathlib import Path
from email.mime.text import MIMEText
from datetime import datetime

from dotenv import load_dotenv
import psycopg2
import psycopg2.extras
from gigachat import GigaChat
from gigachat.exceptions import NotFoundError

# 1. Настройки из .env
load_dotenv(Path(__file__).resolve().parent / ".env")

GIGACHAT_AUTH_KEY = os.getenv("GIGACHAT_AUTH_KEY")

PG_DSN   = os.getenv("PG_DSN")                      # тащится из .env postgresql+psycopg2://user:user@host:5432/db
PG_TABLE = os.getenv("PG_TABLE") # тоже тащится из .env - имя таблицы с событиями
PG_LIMIT = int(os.getenv("PG_LIMIT"))        # зашито на месте - сколько последних событий брать

SMTP_HOST     = os.getenv("SMTP_HOST", "smtp.yandex.ru")
SMTP_PORT     = int(os.getenv("SMTP_PORT", "465"))
SMTP_USER     = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
ALERT_TO      = os.getenv("ALERT_TO")

missing = [n for n, v in {
    "GIGACHAT_AUTH_KEY": GIGACHAT_AUTH_KEY,
    "PG_DSN": PG_DSN,
    "SMTP_USER": SMTP_USER,
    "SMTP_PASSWORD": SMTP_PASSWORD,
    "ALERT_TO": ALERT_TO,
}.items() if not v]
if missing:
    raise SystemExit(f"Ошибка: в .env не заданы переменные: {', '.join(missing)}")

# PG_DSN у нас в формате sqlalchemy, а psycopg2 нужны чистые параметры.
# Приводим: postgresql+psycopg2://user:pass@host:port/db -> postgres://user:pass@host:port/db
pg_conn_dsn = PG_DSN.replace("postgresql+psycopg2://", "postgresql://")

# 2. Выгружаем события из Postgres и пишем в JSON-файл
JSON_PATH = Path(__file__).resolve().parent / "events.json"

print(f"Подключаюсь к Postgres, выгружаю последние {PG_LIMIT} событий...")

query = f"""
    SELECT id, event_time, event_type, event_id, level,
           username, source, action, result, computer, created_at
    FROM {PG_TABLE}
    ORDER BY event_time DESC
    LIMIT %s
"""

with psycopg2.connect(pg_conn_dsn) as conn:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(query, (PG_LIMIT,))
        rows = cur.fetchall()

def iso(value):
    """TIMESTAMPTZ -> строка ISO 8601."""
    if isinstance(value, datetime):
        return value.isoformat()
    return value

events = []
for row in rows:
    events.append({k: iso(v) for k, v in row.items()})

with open(JSON_PATH, "w", encoding="utf-8") as f:
    json.dump(events, f, ensure_ascii=False, indent=2)

print(f"События сохранены в {JSON_PATH} ({len(events)} записей)")

if not events:
    raise SystemExit("Таблица пуста — анализировать нечего.")

# 3. Промпт аналитика безопасности
logs_json = json.dumps(events, ensure_ascii=False, indent=2)

QUESTION = (
    "Ты — аналитик по информационной безопасности. Ниже в формате JSON — журнал "
    "событий безопасности (успешные и неуспешные входы, действия пользователей, события систем).\n\n"
    "Проанализируй журнал и дай отчёт:\n"
    "1. Общая сводка: сколько событий, по типам (event_type) и уровням (level).\n"
    "2. Подозрительные активности: неуспешные входы подряд, входы в нерабочее время, "
    "редкие source/computer, аномальные username.\n"
    "3. Топ-3 наиболее подозрительных события — процитируй их id и кратко объясни, почему.\n"
    "4. Рекомендации: что стоит проверить или настроить.\n\n"
    "Отвечай на русском языке, структурированно, без лишней воды.\n\n"
    f"Журнал событий:\n{logs_json}"
)

# 4. Отправляем в GigaChat (модель выбираем из доступных, как в v3)
print("Запрашиваю список моделей...")
with GigaChat(credentials=GIGACHAT_AUTH_KEY, verify_ssl_certs=False) as giga:
    available = [m.id_ for m in giga.get_models().data
                 if not m.id_.startswith("Embeddings")]
print("Доступные чат-модели:", ", ".join(available))
if not available:
    raise SystemExit("Чат-модели не найдены.")

model_name = available[0]
print(f"Задаю модель: {model_name}, отправляю журнал на анализ...")

with GigaChat(credentials=GIGACHAT_AUTH_KEY,
              model=model_name,
              verify_ssl_certs=False) as giga:
    response = giga.chat(QUESTION)
    answer = response.choices[0].message.content

print("\nАнализ получен:")
print(answer[:300], "...")

# Сохраняем отчёт рядом с JSON — для истории проекта
report_path = Path(__file__).resolve().parent / f"report_{datetime.now():%Y%m%d_%H%M%S}.txt"
report_path.write_text(answer, encoding="utf-8")
print(f"Отчёт сохранён в {report_path.name}")

# 5. Отправляем отчёт письмом
print(f"\nОтправляю письмо на {ALERT_TO}...")

body = (
    f"Автоотчёт log-analyzer от {datetime.now():%Y-%m-%d %H:%M}\n"
    f"Модель: {model_name}\n"
    f"Проанализировано событий: {len(events)} (файл {JSON_PATH.name})\n"
    "----------------------------------------\n\n"
    f"{answer}\n"
)

msg = MIMEText(body, "plain", "utf-8")
msg["From"] = SMTP_USER
msg["To"] = ALERT_TO
msg["Subject"] = f"log-analyzer: отчёт по событиям безопасности ({len(events)} шт., {model_name})"

with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as server:
    server.login(SMTP_USER, SMTP_PASSWORD)
    server.send_message(msg)

print("Письмо отправлено! Проверьте ящик.")
