# bot.py
import os
import sys
import json
import hashlib
import argparse
import requests
from typing import Dict, List, Optional
from getdata import fetch_tracking_info

# ── Настройки ─────────────────────────────────────────────
SUBSCRIPTIONS_FILE = "subscriptions.json"
OFFSET_FILE = "last_update_id.txt"

def get_token() -> str:
    """Получает токен: аргумент --token > переменная окружения > ввод с клавиатуры."""
    parser = argparse.ArgumentParser(description="Telegram бот для отслеживания посылок")
    parser.add_argument("--token", help="Токен Telegram бота")
    args, _ = parser.parse_known_args()
    if args.token:
        return args.token
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    if token:
        return token
    # Для локального запуска можно ввести вручную
    if sys.stdin.isatty():
        return input("Введите токен Telegram бота: ").strip()
    raise RuntimeError("Не задан TELEGRAM_BOT_TOKEN (ни через --token, ни через переменную окружения)")

TOKEN = get_token()
API_URL = f"https://api.telegram.org/bot{TOKEN}"
ADMIN_CHAT_ID = os.environ.get("ADMIN_CHAT_ID")

# ── Работа с файлами ──────────────────────────────────────

def load_subscriptions() -> Dict[int, dict]:
    """Загружает подписки { chat_id: { 'code': ..., 'hash': ... } }."""
    try:
        with open(SUBSCRIPTIONS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return {int(k): v for k, v in data.items()}
    except FileNotFoundError:
        return {}

def save_subscriptions(subs: Dict[int, dict]):
    """Сохраняет подписки в JSON."""
    with open(SUBSCRIPTIONS_FILE, "w", encoding="utf-8") as f:
        json.dump({str(k): v for k, v in subs.items()}, f, ensure_ascii=False, indent=2)

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
    """Отправляет сообщение пользователю."""
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

def get_updates(offset: int) -> List[dict]:
    """Получает новые сообщения от Telegram."""
    url = f"{API_URL}/getUpdates"
    params = {"offset": offset, "timeout": 10}
    try:
        resp = requests.get(url, params=params, timeout=15)
        resp.raise_for_status()
        return resp.json().get("result", [])
    except Exception as e:
        print(f"Ошибка getUpdates: {e}")
        return []

# ── Обработка команд ─────────────────────────────────────

from datetime import datetime  # добавьте этот импорт в начало bot.py


def _format_event_line(ev: dict, index: Optional[int] = None) -> str:
    """Форматирует одно событие для вывода."""
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


def format_status(data: dict) -> str:
    """Форматирует статус посылки: первое событие рядом со статусом, затем три следующих."""
    d = data["data"]
    track = d["trackCode"]
    delivered = d.get("deliveredStatus") == "1"
    status = "✅ доставлено" if delivered else "📦 в пути"
    days_total = d.get("daysInTransit", "?")

    events = d.get("events", [])
    try:
        events_sorted = sorted(
            events,
            key=lambda e: datetime.strptime(e["operationDateTime"], "%d.%m.%Y %H:%M:%S"),
            reverse=True,
        )
    except Exception:
        events_sorted = events

    latest_event = events_sorted[0] if events_sorted else None
    following_events = events_sorted[1:4] if len(events_sorted) > 1 else []

    lines = [
        f"📦 <b>{track}</b>",
        f"Статус: {status}",
        f"Всего дней в пути: {days_total}",
        "",
        "🔔 <b>Текущий статус:</b>",
    ]

    if latest_event:
        lines.append(_format_event_line(latest_event))
    else:
        lines.append("Нет данных")

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
    """Вычисляет хеш состояния для отслеживания изменений."""
    relevant = {
        "events": data["data"]["events"],
        "lastPoint": data["data"]["lastPoint"],
    }
    raw = json.dumps(relevant, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode()).hexdigest()

def process_new_message(chat_id: int, code: str, subs: Dict[int, dict]):
    """Обрабатывает новый трек-код от пользователя."""
    code = code.strip()
    if not (5 <= len(code) <= 28):
        send_message(chat_id, "❌ Неверный формат трек-номера (должен быть от 5 до 28 символов).")
        return subs

    send_message(chat_id, f"🔎 Ищу информацию по треку <b>{code}</b>...")
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

    new_hash = compute_state_hash(data)
    subs[chat_id] = {"code": code, "hash": new_hash}
    send_message(chat_id, "✅ Вы подписались на обновления по этому треку. Я буду проверять изменения.")
    return subs

def check_subscriptions(subs: Dict[int, dict]):
    """Проверяет все подписки и уведомляет об изменениях."""
    for chat_id, info in list(subs.items()):
        code = info["code"]
        old_hash = info["hash"]
        print(f"Проверяю {code} для chat_id={chat_id}...")
        data = fetch_tracking_info(code)
        if data is None:
            print(f"   Не удалось получить данные, пропуск.")
            continue

        new_hash = compute_state_hash(data)
        if new_hash != old_hash:
            try:
                info_msg = "🔄 <b>Обновление по треку!</b>\n\n" + format_status(data)
                send_message(chat_id, info_msg)
                subs[chat_id]["hash"] = new_hash
            except Exception as e:
                print(f"Ошибка отправки уведомления chat_id={chat_id}: {e}")
        else:
            print("   Без изменений.")

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