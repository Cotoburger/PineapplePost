# getdata.py
"""
Модуль для получения и расшифровки данных отслеживания track24.ru.
Использует cloudscraper для обхода защиты Cloudflare.
"""

import sys
import re
import json
import base64
import hashlib
import uuid as _uuid
from urllib.parse import urljoin
from typing import Dict, Optional

import cloudscraper
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


BASE_URL = "https://track24.ru"
AJAX_PATH = "/ajax/c9bad3a632982e4e315b3ef3d6567e23.ajax.php"
DEBUG_JS_FILE = "page_js_dump.txt"


def evp_kdf(passphrase: str, salt: bytes, key_size=32, iv_size=16) -> tuple:
    target_size = key_size + iv_size
    derived, block = b"", b""
    while len(derived) < target_size:
        md5 = hashlib.md5()
        md5.update(block)
        md5.update(passphrase.encode("utf-8"))
        md5.update(salt)
        block = md5.digest()
        derived += block
    return derived[:key_size], derived[key_size:key_size + iv_size]


def decrypt_response(encrypted_json: dict, password: str) -> dict:
    ct = base64.b64decode(encrypted_json["ct"])
    iv = bytes.fromhex(encrypted_json["iv"])
    salt = bytes.fromhex(encrypted_json["s"])
    key, _ = evp_kdf(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext_padded = cipher.decrypt(ct)
    plaintext = unpad(plaintext_padded, AES.block_size)
    return json.loads(plaintext.decode("utf-8"))


def extract_var(var_name: str, text: str) -> Optional[str]:
    patterns = [
        rf'(?:var|let|const)\s+{var_name}\s*=\s*"(.*?)"\s*;',
        rf'(?:var|let|const)\s+{var_name}\s*=\s*\'(.*?)\'\s*;',
        rf'{var_name}\s*=\s*"(.*?)"\s*;',
        rf'{var_name}\s*=\s*\'(.*?)\'\s*;',
        rf'{var_name}\s*=\s*([^;]+?)\s*;',
    ]
    for pat in patterns:
        m = re.search(pat, text)
        if m:
            val = m.group(1).strip()
            if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                val = val[1:-1]
            if val in ("null", "undefined", ""):
                return None
            return val
    return None


def decode_js_escapes(s: str) -> str:
    return re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), s)


def _fetch_tracking_page(tracking_code: str, session) -> str:
    resp = session.get(BASE_URL + "/", params={"code": tracking_code})
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")
    scripts = soup.find_all("script")
    return "\n".join(script.string for script in scripts if script.string)


def _extract_parameters(js_text: str, html_text: str = "") -> dict:
    params = {}
    for name in ["trackingKey", "clientIp", "uuid", "cp"]:
        val = extract_var(name, js_text)
        if not val and html_text:
            m = re.search(rf'data-{re.escape(name)}="([^"]+)"', html_text)
            if m:
                val = m.group(1)
        params[name] = val

    cp_raw = params.get("cp")
    password = decode_js_escapes(cp_raw) if cp_raw else None

    return {
        "tracking_key": params.get("trackingKey"),
        "client_ip": params.get("clientIp"),
        "uuid": params.get("uuid"),
        "password": password,
    }


def fetch_tracking_info(tracking_code: str) -> Optional[Dict]:
    session = cloudscraper.create_scraper()
    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.0 Safari/605.1.15"
        ),
        "Accept-Language": "en-US,en;q=0.9",
    })

    # 1. Загружаем страницу и получаем JS
    resp = session.get(BASE_URL + "/", params={"code": tracking_code})
    resp.raise_for_status()
    html_text = resp.text
    soup = BeautifulSoup(html_text, "html.parser")
    scripts = soup.find_all("script")
    js_text = "\n".join(script.string for script in scripts if script.string)

    # Сохраняем JS для диагностики
    try:
        with open(DEBUG_JS_FILE, "w", encoding="utf-8") as f:
            f.write(js_text)
    except Exception:
        pass

    # 2. Параметры
    params = _extract_parameters(js_text, html_text)

    if not params["tracking_key"] or not params["client_ip"]:
        print("⚠️ Не удалось найти trackingKey или clientIp. Фрагменты JS и HTML:", file=sys.stderr)
        print("--- JS (первые 2000) ---", file=sys.stderr)
        print(js_text[:2000], file=sys.stderr)
        print("--- HTML (первые 2000) ---", file=sys.stderr)
        print(html_text[:2000], file=sys.stderr)
        print("--- Конец отладки ---", file=sys.stderr)
        return None
    else:
        print(f"Параметры: trackingKey={params['tracking_key']}, clientIp={params['client_ip']}, uuid={params['uuid']}, password={'***' if params['password'] else 'None'}")

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
        print(f"Ошибка API: {e}", file=sys.stderr)
        return None

    if "ct" not in encrypted:
        print("Ответ без ct", file=sys.stderr)
        return None

    try:
        return decrypt_response(encrypted, password)
    except Exception as e:
        print(f"Ошибка расшифровки: {e}", file=sys.stderr)
        return None


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