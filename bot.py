# bot.py
import os
import html as html_lib
from urllib.parse import quote
import sys
import json
import hashlib
import base64
import argparse
import requests
from typing import Dict, Optional
from datetime import datetime
from getdata import fetch_tracking_info
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

DEBUG_ENCRYPTION_SECRET = None




SUBSCRIPTIONS_FILE = "subscriptions.json"
OFFSET_FILE = "last_update_id.txt"

def get_token() -> str:
    parser = argparse.ArgumentParser()
    parser.add_argument("--token", help="Токен Telegram бота")
    args, _ = parser.parse_known_args()
    if args.token:
        return args.token
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    if token:
        return token
    if sys.stdin.isatty():
        return input("Введите токен Telegram бота: ").strip()
    raise RuntimeError("Не задан TELEGRAM_BOT_TOKEN")

TOKEN = get_token()
API_URL = f"https://api.telegram.org/bot{TOKEN}"

env_secret = os.environ.get("ENCRYPTION_SECRET")
if env_secret:
    ENCRYPTION_SECRET = env_secret
elif DEBUG_ENCRYPTION_SECRET:
    ENCRYPTION_SECRET = DEBUG_ENCRYPTION_SECRET
    print("⚠️ Используется DEBUG_ENCRYPTION_SECRET из кода (не для production!)")
else:
    ENCRYPTION_SECRET = None

if ENCRYPTION_SECRET:
    ENC_KEY = hashlib.sha256(ENCRYPTION_SECRET.encode()).digest()
else:
    ENC_KEY = None
    print("⚠️ ENCRYPTION_SECRET не задан. Подписки будут храниться без шифрования.")

# ── Шифрование/расшифрование подписок ─────────────────────
def encrypt_subscriptions(data: dict) -> str:
    """Шифрует словарь подписок и возвращает base64-строку."""
    plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")
    iv = os.urandom(16)
    cipher = AES.new(ENC_KEY, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return base64.b64encode(iv + ciphertext).decode("ascii")

def decrypt_subscriptions(encrypted_b64: str) -> Optional[dict]:
    """Расшифровывает base64-строку в словарь подписок."""
    try:
        raw = base64.b64decode(encrypted_b64)
        iv = raw[:16]
        ciphertext = raw[16:]
        cipher = AES.new(ENC_KEY, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return json.loads(plaintext.decode("utf-8"))
    except Exception as e:
        print(f"Ошибка расшифровки подписок: {e}")
        return None

import traceback

def load_subscriptions() -> Dict[int, dict]:
    try:
        with open(SUBSCRIPTIONS_FILE, "r", encoding="utf-8") as f:
            raw = f.read().strip()
            if not raw:
                return {}
    except FileNotFoundError:
        return {}

    if ENC_KEY:
        # Пробуем расшифровать
        try:
            raw_bytes = base64.b64decode(raw)
        except Exception:
            print("Ошибка: файл подписок содержит некорректный Base64.")
            return {}

        if len(raw_bytes) < 16 or len(raw_bytes) % 16 != 0:
            print(f"Ошибка: размер зашифрованных данных ({len(raw_bytes)} байт) не кратен 16.")
            return {}

        iv = raw_bytes[:16]
        ciphertext = raw_bytes[16:]
        try:
            cipher = AES.new(ENC_KEY, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            data = json.loads(plaintext.decode("utf-8"))
            return {int(k): v for k, v in data.items()}
        except Exception as e:
            print(f"Не удалось расшифровать подписки: {e}")
            # Если расшифровка не удалась, возможно, ключ изменился или файл повреждён.
            # Резервное копирование повреждённого файла и старт с чистого листа
            backup = SUBSCRIPTIONS_FILE + ".bak"
            try:
                os.rename(SUBSCRIPTIONS_FILE, backup)
                print(f"Повреждённый файл подписок переименован в {backup}")
            except Exception:
                pass
            return {}
    else:
        # Без шифрования – обычный JSON
        try:
            data = json.loads(raw)
            return {int(k): v for k, v in data.items()}
        except Exception as e:
            print(f"Ошибка чтения открытых подписок: {e}")
            return {}


def save_subscriptions(subs: Dict[int, dict]):
    data_to_save = {str(k): v for k, v in subs.items()}
    if ENC_KEY:
        content = encrypt_subscriptions(data_to_save)
    else:
        content = json.dumps(data_to_save, ensure_ascii=False, indent=2)
    with open(SUBSCRIPTIONS_FILE, "w", encoding="utf-8") as f:
        f.write(content)

# ── Смещение последнего обработанного обновления ─────────
def get_last_update_id() -> int:
    try:
        with open(OFFSET_FILE, "r") as f:
            return int(f.read().strip())
    except FileNotFoundError:
        return 0

def set_last_update_id(update_id: int):
    with open(OFFSET_FILE, "w") as f:
        f.write(str(update_id))

# ── Telegram API ─────────────────────────────────────────
def send_message(chat_id: int, text: str, parse_mode="HTML", disable_notification=False):
    url = f"{API_URL}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": parse_mode,
        "disable_notification": disable_notification,
    }
    try:
        resp = requests.post(url, json=payload, timeout=10)
        resp.raise_for_status()
    except Exception as e:
        print(f"Ошибка отправки сообщения chat_id={chat_id}: {e}")

def get_updates(offset: int):
    url = f"{API_URL}/getUpdates"
    params = {"offset": offset, "timeout": 10}
    try:
        resp = requests.get(url, params=params, timeout=15)
        resp.raise_for_status()
        return resp.json().get("result", [])
    except Exception as e:
        print(f"Ошибка getUpdates: {e}")
        return []

# ── Форматирование статуса ───────────────────────────────
def _format_event_line(ev: dict, index: Optional[int] = None) -> str:
    dt = ev.get("operationDateTime", "—")
    attr = ev.get("operationAttributeTranslated") or ev.get("operationAttribute", "—")
    place = ev.get("operationPlaceNameTranslated") or ev.get("operationPlaceName", "")
    postal = ev.get("operationPlacePostalCode", "")
    if postal:
        place = f"{postal}, {place}" if place else postal
    service = ev.get("serviceName", "")
    days_event = ev.get("daysInTransit")
    weight = ev.get("itemWeight", 0)

    line = f"{index}. {dt} — {attr}" if index is not None else f"{dt} — {attr}"
    if place:
        line += f" ({place})"
    if service:
        line += f" [{service}]"
    extras = []
    if days_event is not None:
        extras.append(f"{days_event} дн.")
    if weight and weight > 0:
        extras.append(f"{weight/1000:.2f} кг" if weight >= 1000 else f"{weight} г")
    if extras:
        line += " | " + ", ".join(extras)
    return line

# Ключевые слова в тексте события, указывающие на то, что посылка прибыла
# в пункт выдачи и ждёт получателя (или уже вручена).
# Используются как резервный признак, если поле deliveredStat не пришло или не распознано.
_DELIVERED_KEYWORDS = (
    "вручен",
    "выдан",
    "получен",
    "доставлен",
    "delivered",
    "поступил",
    "заберите",
    "пункт выдачи",
    "готов к выдаче",
    "arrival at delivery office",
    "awaiting buyer to pick-up",
    "ready for pickup",
    "arrived at pickup",
)


def _is_delivered(d: dict, latest_event: Optional[dict]) -> bool:
    # 1) Пытаемся понять по полю deliveredStat (или его старому названию deliveredStatus)
    raw = d.get("deliveredStat", d.get("deliveredStatus"))
    if raw is not None:
        if isinstance(raw, bool):
            if raw:
                return True
        elif isinstance(raw, (int, float)):
            if raw == 1:
                return True
        elif isinstance(raw, str):
            if raw.strip().lower() in ("1", "true", "yes", "да"):
                return True

    # 2) Резервная проверка по тексту последнего события (включая operationType)
    if latest_event:
        text = " ".join([
            str(latest_event.get("operationAttributeTranslated") or ""),
            str(latest_event.get("operationAttribute") or ""),
            str(latest_event.get("operationType") or ""),
        ]).lower()
        if any(kw in text for kw in _DELIVERED_KEYWORDS):
            return True

    return False

def _get_sorted_events(data: dict):
    """
    Возвращает события, отсортированные по дате, новые сверху.
    Если дата не парсится, возвращает исходный список.
    """
    events = data.get("data", {}).get("events", [])

    try:
        return sorted(
            events,
            key=lambda e: datetime.strptime(e["operationDateTime"], "%d.%m.%Y %H:%M:%S"),
            reverse=True,
        )
    except Exception:
        return events


def is_delivered(data: dict) -> bool:
    """
    Проверяет, прибыла/вручена/готова ли посылка к выдаче.
    Использует ту же логику, что и format_status.
    """
    if not isinstance(data, dict):
        return False

    d = data.get("data", {}) or {}
    events_sorted = _get_sorted_events(data)
    latest_event = events_sorted[0] if events_sorted else None

    return _is_delivered(d, latest_event)


def format_status(data: dict) -> str:
    d = data["data"]
    track = d["trackCode"]
    days_total = d.get("daysInTransit", "?")

    events_sorted = _get_sorted_events(data)
    latest_event = events_sorted[0] if events_sorted else None
    following_events = events_sorted[1:4] if len(events_sorted) > 1 else []

    delivered = _is_delivered(d, latest_event)
    status = "🏁 прибыло" if delivered else "📦 в пути"

    track_url = f"https://track24.ru/?code={quote(str(track), safe='')}"
    track_html = html_lib.escape(track)
    url_html = html_lib.escape(track_url, quote=True)

    lines = [
        f'📦 <a href="{url_html}">{track_html}</a>',
        f"Статус: {status}",
        f"Всего дней в пути: {days_total}",
        "",
        "🔔 <b>Текущий статус:</b>",
    ]

    if latest_event:
        lines.append(_format_event_line(latest_event))
    else:
        lines.append("Нет данных")

    # История перемещений показывается только пока посылка ещё в пути.
    # Как только заказ прибыл, лишние детали в сообщении убираются.
    if not delivered:
        if following_events:
            lines.append("")
            lines.append("📋 <b>История:</b>")
            for i, ev in enumerate(following_events, 1):
                lines.append(_format_event_line(ev, index=i))
        else:
            lines.append("")
            lines.append("📋 <b>История:</b>")
            lines.append("Нет данных")

    return "\n".join(lines)

def compute_state_hash(data: dict) -> str:
    """
    Считает хэш только от текущего статуса (последнего события).
    Уведомление придёт только когда самое свежее событие изменится.
    """
    events = data["data"]["events"]
    # Сортируем для стабильного порядка
    try:
        events_sorted = sorted(
            events,
            key=lambda e: datetime.strptime(e["operationDateTime"], "%d.%m.%Y %H:%M:%S"),
            reverse=True,
        )
    except Exception:
        events_sorted = events
    
    # Берём только последнее (самое свежее) событие
    latest_event = events_sorted[0] if events_sorted else None
    
    if latest_event is None:
        return hashlib.sha256(b"").hexdigest()
    
    raw = json.dumps(latest_event, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode()).hexdigest()

def process_new_message(chat_id: int, code: str, subs: Dict[int, dict]):
    code = code.strip()

    if not (5 <= len(code) <= 28):
        send_message(chat_id, "❌ Неверный формат трек-номера (должен быть от 5 до 28 символов).")
        return subs

    send_message(chat_id, f"🔎 Ищу информацию по треку <b>{html_lib.escape(code)}</b>...")

    data = fetch_tracking_info(code)

    if data is None:
        send_message(chat_id, "⚠️ Не удалось получить данные. Попробуйте позже.")
        return subs

    try:
        info = format_status(data)
        send_message(chat_id, info)
    except Exception as e:
        send_message(chat_id, f"Ошибка при форматировании: {e}")
        return subs

    # Если посылка уже прибыла/вручена, не добавляем её в отслеживание.
    if is_delivered(data):
        send_message(chat_id, "ℹ️ Посылка уже прибыла/вручена, поэтому отслеживание не добавлено.")
        return subs

    new_hash = compute_state_hash(data)
    subs[chat_id] = {"code": code, "hash": new_hash}

    send_message(chat_id, "✅ Вы подписались на обновления по этому треку. Я буду проверять изменения.")

    return subs

def check_subscriptions(subs: Dict[int, dict]):
    for chat_id, info in list(subs.items()):
        code = info["code"]
        old_hash = info["hash"]

        print(f"Проверяю {code} для chat_id={chat_id}...")

        data = fetch_tracking_info(code)

        if data is None:
            print("   Не удалось получить данные, пропуск.")
            continue

        delivered = is_delivered(data)
        new_hash = compute_state_hash(data)

        # Если посылка прибыла/вручена — отправляем финальное уведомление
        # и удаляем трек из подписок.
        if delivered:
            try:
                info_msg = "🏁 <b>Посылка прибыла!</b>\n\n" + format_status(data)
                send_message(chat_id, info_msg)
            except Exception as e:
                print(f"Ошибка отправки уведомления chat_id={chat_id}: {e}")

            subs.pop(chat_id, None)
            print(f"   Трек {code} удалён из подписок chat_id={chat_id}, так как посылка прибыла.")
            continue

        if new_hash != old_hash:
            try:
                info_msg = "🔄 <b>Обновление по треку!</b>\n\n" + format_status(data)
                send_message(chat_id, info_msg)
                subs[chat_id]["hash"] = new_hash
            except Exception as e:
                print(f"Ошибка отправки уведомления chat_id={chat_id}: {e}")
        else:
            print("   Без изменений.")

# ── Главная функция ──────────────────────────────────────
def main():
    print("Запуск бота...")
    subs = load_subscriptions()
    print(f"Загружено подписок: {len(subs)}")

    # 1. Обработка новых сообщений
    offset = get_last_update_id() + 1
    updates = get_updates(offset)
    if updates:
        print(f"Получено {len(updates)} новых сообщений.")
        for upd in updates:
            update_id = upd["update_id"]
            if update_id > get_last_update_id():
                set_last_update_id(update_id)
            if "message" not in upd:
                continue
            msg = upd["message"]
            chat_id = msg["chat"]["id"]
            text = msg.get("text", "").strip()

            if text.startswith("/start"):
                send_message(chat_id, "👋 Привет! Отправь мне трек-номер посылки, и я буду отслеживать её.")
            elif text.startswith("/stop"):
                if chat_id in subs:
                    del subs[chat_id]
                    send_message(chat_id, "🔕 Отслеживание остановлено.")
                else:
                    send_message(chat_id, "🤔 У вас нет активных отслеживаний.")
            else:
                subs = process_new_message(chat_id, text, subs)

        save_subscriptions(subs)

    # 2. Проверка обновлений для всех подписок
    if subs:
        print("Проверяю обновления...")
        check_subscriptions(subs)
        save_subscriptions(subs)

    print("Бот завершил работу.")

if __name__ == "__main__":
    main()