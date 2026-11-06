"""
send_answer_v5.py — модуль проекта log-analyzer (гибридная версия).

Отличия от v4:
  1. Перед отправкой в GigaChat каждое событие размечается Isolation Forest
     (anomaly_score 0..1 + метка is_anomaly).
  2. Сводку по типам и уровням считает код (Counter), а не модель.
  3. Детерминированный слой "жёстких флагов" находит индикаторы инцидента
     (создание учётки, удаление логов, массовое копирование и т.д.) —
     они передаются модели как обязательные, независимо от скоров леса.
  4. Признаки леса включают привилегированную учётку и корреляцию события
     с внешним IP на той же машине (окно +-10 минут).
  5. Промпт с 8 жёсткими правилами и обязательным вердиктом
     ("инцидент" / "подозрительно" / "ложная тревога").

Выгружает события из Postgres в JSON, отправляет размеченный журнал
GigaChat на анализ и присылает отчёт письмом.
"""
import os
import json
import math
import smtplib
from pathlib import Path
from collections import Counter
from email.mime.text import MIMEText
from datetime import datetime, timedelta

from dotenv import load_dotenv
import psycopg2
import psycopg2.extras
from gigachat import GigaChat
from gigachat.exceptions import NotFoundError

from sklearn.ensemble import IsolationForest
import numpy as np

# 1. Настройки из .env
load_dotenv(Path(__file__).resolve().parent / ".env")

GIGACHAT_AUTH_KEY = os.getenv("GIGACHAT_AUTH_KEY")

PG_DSN   = os.getenv("PG_DSN")   # postgresql+psycopg2://user:user@host:5432/db
PG_TABLE = os.getenv("PG_TABLE")
PG_LIMIT = int(os.getenv("PG_LIMIT"))

# Настройки Isolation Forest (необязательные, есть значения по умолчанию)
IF_CONTAMINATION = float(os.getenv("IF_CONTAMINATION", "0.05"))
IF_MIN_EVENTS    = int(os.getenv("IF_MIN_EVENTS", "10"))

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

# postgresql+psycopg2://... -> postgresql://...
pg_conn_dsn = PG_DSN.replace("postgresql+psycopg2://", "postgresql://")

# ---------------------------------------------------------------------------
# Константы для разметки
# ---------------------------------------------------------------------------
FAIL_RESULTS = {"failed", "fail", "denied", "failure", "error", "0", "false"}

PRIV_USERS = {"admin", "administrator", "root"}   # + любые *_svc (проверяется по суффиксу)

INTERNAL_IP_PREFIXES = ("10.", "192.168.", "127.")
def is_internal_ip(ip: str) -> bool:
    """172.16-31.* проверяем отдельно, остальные — по префиксам."""
    if not isinstance(ip, str):
        return False
    if ip.startswith(INTERNAL_IP_PREFIXES):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            return 16 <= second <= 31
        except (ValueError, IndexError):
            return False
    return False

CORRELATION_WINDOW = timedelta(minutes=10)  # окно для связи события с внешним вторжением

# Жёсткие детерминированные индикаторы инцидента (ищутся по action).
# Считаются кодом, а не моделью — модель не может их "не заметить".
HARD_PATTERNS = [
    ("создание учётной записи", ["create_user", "new_user", "user_add", "net user /add", "account created"]),
    ("удаление/очистка логов",  ["delete_log", "clear_log", "log_delete", "clear logs", "log cleared", "delete logs"]),
    ("массовое копирование",    ["mass_file_copy", "bulk_copy", "file_copy", "mass_copy"]),
    ("установка службы",        ["install_service", "service_install", "new_service", "create service"]),
    ("encoded PowerShell",      ["powershell_encoded", "-enc", "encoded"]),
    ("остановка защитной службы", ["stop_protection", "stop_service", "service stopped", "disable_protection"]),
]

# 2. Выгружаем события из Postgres
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

# Убираем возможный дубль колонки при SELECT (psycopg2 RealDictCursor оставит последнюю)
# и парсим время событий для признаков/корреляции.
def parse_dt(value):
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None

for ev in events:
    ev["event_time_dt"] = parse_dt(ev.get("event_time"))

print(f"События выгружены: {len(events)} записей")

if not events:
    raise SystemExit("Таблица пуста — анализировать нечего.")

# ---------------------------------------------------------------------------
# 3. Признаки для Isolation Forest
# ---------------------------------------------------------------------------
KNOWN_EVENT_TYPES = ["login", "process", "network", "file", "service", "share_access", "account"]
KNOWN_LEVELS = ["INFO", "WARNING", "WARN", "CRITICAL"]

# счётчики по журналу (для редкости и серии неудач)
type_action_counter = Counter(
    (e.get("event_type", ""), str(e.get("action", "")).lower()) for e in events
)
failed_by_user = Counter(
    e.get("username", "") for e in events
    if str(e.get("result", "")).lower() in FAIL_RESULTS
)

# индекс: computer -> список (время, событие с внешним source)
external_by_computer = {}
for e in events:
    if not is_internal_ip(e.get("source", "")) and e.get("event_time_dt"):
        external_by_computer.setdefault(e.get("computer", ""), []).append(e["event_time_dt"])

def build_features(ev, total):
    """Числовой вектор признаков одного события."""
    et = ev.get("event_type", "")
    lv = str(ev.get("level", "")).upper()
    action = str(ev.get("action", "")).lower()
    username = ev.get("username", "") or ""
    source = ev.get("source", "") or ""
    dt = ev["event_time_dt"]

    feats = []
    # one-hot по типу события
    for t in KNOWN_EVENT_TYPES:
        feats.append(1.0 if et == t else 0.0)
    # one-hot по уровню
    for l in KNOWN_LEVELS:
        feats.append(1.0 if lv == l else 0.0)

    if dt:
        hour = dt.hour + dt.minute / 60.0
        feats.append(math.sin(2 * math.pi * hour / 24))
        feats.append(math.cos(2 * math.pi * hour / 24))
        feats.append(1.0 if (dt.hour >= 22 or dt.hour < 6) else 0.0)  # ночь
    else:
        feats.extend([0.0, 0.0, 0.0])

    # внешний/внутренний источник
    feats.append(0.0 if is_internal_ip(source) else 1.0)

    # неуспешный вход
    is_failed = str(ev.get("result", "")).lower() in FAIL_RESULTS
    feats.append(1.0 if is_failed else 0.0)

    # нормированный счётчик неудачных входов пользователя
    total_failed = sum(failed_by_user.values())
    feats.append(failed_by_user[username] / total_failed if total_failed else 0.0)

    # редкая пара (тип события, действие): частота <= 2% журнала
    freq = type_action_counter[(et, action)] / total if total else 0.0
    feats.append(1.0 if freq <= 0.02 else 0.0)

    # привилегированная учётка
    priv = username.lower() in PRIV_USERS or username.lower().endswith("_svc")
    feats.append(1.0 if priv else 0.0)

    # корреляция с внешним вторжением: на этой машине в окне +-10 мин был внешний IP
    correlated = 0.0
    if dt is not None:
        for ext_dt in external_by_computer.get(ev.get("computer", ""), []):
            if abs((ext_dt - dt).total_seconds()) <= CORRELATION_WINDOW.total_seconds():
                correlated = 1.0
                break
    feats.append(correlated)

    return feats

# ---------------------------------------------------------------------------
# 4. Isolation Forest: скоринг аномалий
# ---------------------------------------------------------------------------
print(f"Isolation Forest: contamination={IF_CONTAMINATION}, порог обучения={IF_MIN_EVENTS} событий...")

iforest_on = len(events) >= IF_MIN_EVENTS
X = np.array([build_features(e, len(events)) for e in events])

if iforest_on:
    model = IsolationForest(
        n_estimators=200,
        contamination=IF_CONTAMINATION,
        random_state=42,
    )
    model.fit(X)
    raw = model.decision_function(X)          # чем меньше, тем аномальнее
    lo, hi = raw.min(), raw.max()
    span = (hi - lo) if hi > lo else 1.0
    scores = 1.0 - (raw - lo) / span          # нормируем в 0..1, выше = аномальнее
    labels = model.predict(X)                 # -1 = аномалия
    for e, s, lab in zip(events, scores, labels):
        e["anomaly_score"] = round(float(s), 4)
        e["is_anomaly"] = bool(lab == -1)
    n_anomalies = sum(1 for e in events if e["is_anomaly"])
    print(f"Isolation Forest: {n_anomalies} аномалий из {len(events)} событий")
else:
    for e in events:
        e["anomaly_score"] = 0.5              # нейтральный скор
        e["is_anomaly"] = False
    n_anomalies = 0
    print(f"Isolation Forest отключён: событий меньше {IF_MIN_EVENTS} (мало данных для обучения)")

# Убираем служебное поле перед сохранением и отправкой
for e in events:
    e.pop("event_time_dt", None)

with open(JSON_PATH, "w", encoding="utf-8") as f:
    json.dump(events, f, ensure_ascii=False, indent=2)
print(f"События с разметкой сохранены в {JSON_PATH}")

# ---------------------------------------------------------------------------
# 5. Сводка — считает код, а не модель
# ---------------------------------------------------------------------------
type_counts = Counter(e.get("event_type", "?") for e in events)
level_counts = Counter(str(e.get("level", "?")).upper() for e in events)

summary_lines = [f"Всего событий: {len(events)}"]
summary_lines.append("По типам: " + ", ".join(f"{k}: {v}" for k, v in sorted(type_counts.items())))
summary_lines.append("По уровням: " + ", ".join(f"{k}: {v}" for k, v in sorted(level_counts.items())))
summary_text = "\n".join(summary_lines)

# ---------------------------------------------------------------------------
# 6. Жёсткие индикаторы инцидента (детерминированные правила)
# ---------------------------------------------------------------------------
hard_flags = []
for ev in events:
    action = str(ev.get("action", "")).lower()
    for label, keys in HARD_PATTERNS:
        if any(k in action for k in keys):
            hard_flags.append({
                "id": ev.get("id"),
                "indicator": label,
                "action": ev.get("action"),
                "source": ev.get("source"),
                "username": ev.get("username"),
                "computer": ev.get("computer"),
                "event_time": ev.get("event_time"),
                "anomaly_score": ev.get("anomaly_score"),
            })
hard_text = json.dumps(hard_flags, ensure_ascii=False, indent=2) if hard_flags else "[]"
print(f"Жёсткие индикаторы инцидента: {len(hard_flags)}")

# ---------------------------------------------------------------------------
# 7. Промпт аналитика безопасности (8 жёстких правил)
# ---------------------------------------------------------------------------
logs_json = json.dumps(events, ensure_ascii=False, indent=2)

QUESTION = (
    "Ты — аналитик по информационной безопасности. Ниже в формате JSON — журнал событий "
    "безопасности. Каждое событие размечено Isolation Forest: поля anomaly_score (0..1) "
    "и is_anomaly.\n\n"
    "ЖЁСТКИЕ ПРАВИЛА:\n"
    "1. Используй только те id, числа и значения, которые есть в данных. "
    "Не уверен — процитируй строку события.\n"
    "2. Каждому событию приписывай только те username, source и computer, что указаны "
    "в ЕГО строке. Не объединяй поля разных событий в одну фразу.\n"
    "3. «Нерабочее время» определяй только по фактическому event_time события.\n"
    "4. Все события с is_anomaly=true перечисли полностью, с id и score — ни одно не пропускай.\n"
    "5. Индикаторы инцидента. Если в журнале есть хотя бы одно из перечисленного — "
    "вердикт обязан быть «инцидент», а не «подозрительно»: создание новой учётной записи, "
    "добавление в административные группы, удаление или очистка лог-файлов, массовое "
    "копирование файлов, установка служб на удалённых машинах, запуск PowerShell с -enc "
    "или encoded-командой, остановка защитной службы, неудачные входы с внешнего IP.\n"
    "6. Неудачные входы из внутренней сети (10.*, 192.168.*, 172.16–31.*) от известного "
    "пользователя: 1–2 попытки подряд без CRITICAL-событий — вероятная ошибка пользователя, "
    "а не атака перебором.\n"
    "7. Ранжируй топ подозрительных событий по комбинации: сначала индикаторы из п.5, "
    "затем высокий anomaly_score, затем CRITICAL-уровень. anomaly_score — вспомогательный "
    "сигнал, а не единственный критерий.\n"
    "8. Заверши отчёт вердиктом — строго одно из: «инцидент», «подозрительно», "
    "«ложная тревога» — с обоснованием.\n\n"
    "Структура отчёта:\n"
    "1. Общая сводка (используй готовые числа из блока СВОДКА — они точные).\n"
    "2. Индикаторы инцидента из п.5, если есть — с id и цитатами строк.\n"
    "3. Подозрительные активности.\n"
    "4. Все события с is_anomaly=true.\n"
    "5. Топ-3 наиболее подозрительных события с объяснением.\n"
    "6. Рекомендации.\n"
    "7. Вердикт.\n\n"
    f"СВОДКА (посчитана кодом, числа точные):\n{summary_text}\n\n"
    f"ИНДИКАТОРЫ ИНЦИДЕНТА (найдены детерминированным правилом, считать обязательными):\n{hard_text}\n\n"
    f"Журнал событий:\n{logs_json}"
)

# 8. Отправляем в GigaChat (модель выбираем из доступных, как в v3/v4)
print("Запрашиваю список моделей...")
with GigaChat(credentials=GIGACHAT_AUTH_KEY, verify_ssl_certs=False) as giga:
    available = [m.id_ for m in giga.get_models().data
                 if not m.id_.startswith("Embeddings")]
print("Доступные чат-модели:", ", ".join(available))
if not available:
    raise SystemExit("Чат-модели не найдены.")

model_name = available[0]
print(f"Задаю модель: {model_name}, отправляю размеченный журнал на анализ...")

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

# 9. Отправляем отчёт письмом
print(f"\nОтправляю письмо на {ALERT_TO}...")

iforest_state = f"on, contamination={IF_CONTAMINATION}" if iforest_on else f"off (<{IF_MIN_EVENTS} событий)"

body = (
    f"Автоотчёт log-analyzer от {datetime.now():%Y-%m-%d %H:%M}\n"
    f"Модель: {model_name} + Isolation Forest ({iforest_state})\n"
    f"Проанализировано событий: {len(events)} (файл {JSON_PATH.name})\n"
    f"Аномалий по Isolation Forest: {n_anomalies}\n"
    f"Жёстких индикаторов инцидента: {len(hard_flags)}\n"
    "----------------------------------------\n\n"
    f"{answer}\n"
)

msg = MIMEText(body, "plain", "utf-8")
msg["From"] = SMTP_USER
msg["To"] = ALERT_TO
msg["Subject"] = (
    f"log-analyzer: отчёт по событиям безопасности "
    f"({len(events)} шт., {len(hard_flags)} индикаторов, {model_name})"
)

with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as server:
    server.login(SMTP_USER, SMTP_PASSWORD)
    server.send_message(msg)

print("Письмо отправлено! Проверьте ящик.")
