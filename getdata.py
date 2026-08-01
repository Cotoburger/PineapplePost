# getdata.py
"""
Модуль для получения и расшифровки данных отслеживания track24.ru.
Может использоваться как самостоятельный скрипт: python getdata.py TRACKCODE
"""

import sys
import re
import json
import base64
import hashlib
import uuid as _uuid
from urllib.parse import urljoin
from typing import Dict, Optional

import requests
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


# ── Константы ──────────────────────────────────────────────
BASE_URL = "https://track24.ru"
AJAX_PATH = "/ajax/c9bad3a632982e4e315b3ef3d6567e23.ajax.php"

# ── Вспомогательные функции ────────────────────────────────

def evp_kdf(passphrase: str, salt: bytes, key_size=32, iv_size=16) -> tuple:
    """Эмуляция CryptoJS EvpKDF (MD5, 1 итерация)."""
    target_size = key_size + iv_size
    derived = b""
    block = b""
    while len(derived) < target_size:
        md5 = hashlib.md5()
        md5.update(block)
        md5.update(passphrase.encode("utf-8"))
        md5.update(salt)
        block = md5.digest()
        derived += block
    return derived[:key_size], derived[key_size:key_size + iv_size]


def decrypt_response(encrypted_json: dict, password: str) -> dict:
    """Расшифровывает JSON вида {"ct":..., "iv":..., "s":...}."""
    ct = base64.b64decode(encrypted_json["ct"])
    iv = bytes.fromhex(encrypted_json["iv"])
    salt = bytes.fromhex(encrypted_json["s"])
    key, _ = evp_kdf(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext_padded = cipher.decrypt(ct)
    plaintext = unpad(plaintext_padded, AES.block_size)
    return json.loads(plaintext.decode("utf-8"))


def extract_var(var_name: str, text: str) -> Optional[str]:
    """Извлекает значение переменной из JavaScript-кода."""
    # var/let/const name = "value"
    pattern = rf'(?:var|let|const)\s+{var_name}\s*=\s*[\'"](.+?)[\'"]\s*;'
    m = re.search(pattern, text)
    if m:
        return m.group(1)
    # name = "value"
    m = re.search(rf'{var_name}\s*=\s*[\'"](.+?)[\'"]\s*;', text)
    return m.group(1) if m else None


def decode_js_escapes(s: str) -> str:
    r"""Преобразует JavaScript escape-последовательности \xHH в настоящие символы."""
    return re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), s)


def _fetch_tracking_page(tracking_code: str, session: requests.Session) -> str:
    """Загружает главную страницу отслеживания и возвращает весь JS-текст."""
    resp = session.get(BASE_URL + "/", params={"code": tracking_code})
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")
    scripts = soup.find_all("script")
    return "\n".join(script.string for script in scripts if script.string)


def _extract_parameters(js_text: str) -> dict:
    """Извлекает trackingKey, clientIp, uuid, cp из JS-кода."""
    params = {}
    params["tracking_key"] = extract_var("trackingKey", js_text)
    params["client_ip"] = extract_var("clientIp", js_text)
    params["uuid"] = extract_var("uuid", js_text)
    cp_raw = extract_var("cp", js_text)
    params["password"] = decode_js_escapes(cp_raw) if cp_raw else None
    return params


# ── Основная функция ──────────────────────────────────────

def fetch_tracking_info(tracking_code: str) -> Optional[Dict]:
    """
    Получает и расшифровывает данные отслеживания для указанного трек-кода.
    Возвращает словарь с расшифрованным JSON или None при ошибке.
    """
    session = requests.Session()
    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.0 Safari/605.1.15"
        ),
        "Accept-Language": "en-US,en;q=0.9",
    })

    # 1. Загружаем страницу и извлекаем параметры
    js_text = _fetch_tracking_page(tracking_code, session)
    params = _extract_parameters(js_text)

    if not params["tracking_key"] or not params["client_ip"]:
        print("Ошибка: не удалось извлечь trackingKey или clientIp", file=sys.stderr)
        return None

    # 2. Если нет uuid — генерируем
    uuid_val = params["uuid"] or str(_uuid.uuid4())
    password = params["password"]
    if not password:
        print("Ошибка: не удалось извлечь ключ cp", file=sys.stderr)
        return None

    # 3. AJAX-запрос
    payload = {
        "code": tracking_code,
        "selectedService": "",
        "lng": "ru",
        "sort": "0",
        "grouped": "false",
        "type": "cache",
        "key": params["tracking_key"],
        "clientIp": params["client_ip"],
        "uuid": uuid_val,
    }

    ajax_headers = {
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Referer": f"{BASE_URL}/?code={tracking_code}",
        "Origin": BASE_URL,
        "X-Requested-With": "XMLHttpRequest",
    }

    try:
        resp = session.post(
            urljoin(BASE_URL, AJAX_PATH),
            data=payload,
            headers=ajax_headers,
            timeout=30
        )
        resp.raise_for_status()
        encrypted = resp.json()
    except Exception as e:
        print(f"Ошибка при запросе к API: {e}", file=sys.stderr)
        return None

    if "ct" not in encrypted:
        print("Ответ не содержит зашифрованных данных", file=sys.stderr)
        return None

    # 4. Расшифровка
    try:
        return decrypt_response(encrypted, password)
    except Exception as e:
        print(f"Ошибка расшифровки: {e}", file=sys.stderr)
        return None


# ── Запуск как скрипт ──────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Использование: python getdata.py TRACKCODE", file=sys.stderr)
        sys.exit(1)
    track = sys.argv[1]
    data = fetch_tracking_info(track)
    if data is None:
        print("Не удалось получить данные", file=sys.stderr)
        sys.exit(1)
    print(json.dumps(data, ensure_ascii=False, indent=2))