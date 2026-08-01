# bot.py
import os
import sys
import json
import hashlib
import base64
import argparse
import requests
from typing import Dict, List, Optional
from getdata import fetch_tracking_info

# --- Шифрование подписок ------------------------------------------------
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

SUBSCRIPTIONS_FILE = "subscriptions.json"
OFFSET_FILE = "last_update_id.txt"
ENCRYPTION_SECRET = os.environ.get("ENCRYPTION_SECRET")  # может быть None

if ENCRYPTION_SECRET:
    # Генерируем 32-байтный ключ из секрета через SHA-256
    ENC_KEY = hashlib.sha256(ENCRYPTION_SECRET.encode()).digest()
else:
    ENC_KEY = None
    print("⚠️ ENCRYPTION_SECRET не задан. Подписки будут храниться без шифрования.")


def encrypt_subscriptions(data: dict) -> str:
    """Шифрует словарь подписок и возвращает base64-строку."""
    plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")
    iv = os.urandom(16)  # случайный IV
    cipher = AES.new(ENC_KEY, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    # Префикс: IV (16 байт) + ciphertext, затем кодируем в base64
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


# --- Работа с файлами (шифрованные или открытые) -------------------------

def load_subscriptions() -> Dict[int, dict]:
    """Загружает подписки из файла (автоопределение формата)."""
    try:
        with open(SUBSCRIPTIONS_FILE, "r", encoding="utf-8") as f:
            raw = f.read().strip()
            if not raw:
                return {}
    except FileNotFoundError:
        return {}

    # Если ENC_KEY задан, считаем файл зашифрованным
    if ENC_KEY:
        data = decrypt_subscriptions(raw)
        if data is None:
            print("Не удалось расшифровать подписки. Возвращаю пустой список.")
            return {}
        return {int(k): v for k, v in data.items()}
    else:
        # Обычный JSON
        try:
            data = json.loads(raw)
            return {int(k): v for k, v in data.items()}
        except Exception as e:
            print(f"Ошибка чтения подписок: {e}")
            return {}


def save_subscriptions(subs: Dict[int, dict]):
    """Сохраняет подписки в файл (шифрует, если задан ключ)."""
    data_to_save = {str(k): v for k, v in subs.items()}
    if ENC_KEY:
        content = encrypt_subscriptions(data_to_save)
    else:
        content = json.dumps(data_to_save, ensure_ascii=False, indent=2)
    with open(SUBSCRIPTIONS_FILE, "w", encoding="utf-8") as f:
        f.write(content)


# --- Остальная часть бота без изменений ---------------------------------
# ... (токен, API, send_message, get_updates, format_status и т.д.)
# Полный код ниже.