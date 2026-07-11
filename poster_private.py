#!/usr/bin/env python3
"""
Private VPN Keys Telegram Poster v2.
Категоризированный постер без пинга и без файла.
Источник: subscriptions_list.txt (список URL по категориям)
Чанки по 100 ключей → инлайн-кнопки с копированием
Приоритет: EU → RU → всё остальное
"""
import os
import sys
import requests
import base64
import re
import time
from datetime import datetime
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Dict, List, Tuple


def get_robust_session(retries=3, backoff_factor=1):
    session = requests.Session()
    retry_strategy = Retry(
        total=retries,
        backoff_factor=backoff_factor,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS"],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


robust_session = get_robust_session()

# --- КОНФИГУРАЦИЯ ---
DRY_RUN = os.environ.get("TELEGRAM_DRY_RUN", "0") == "1"
BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
CHANNEL_ID = os.environ.get("TELEGRAM_PRIVATE_CHANNEL")

WORK_DIR = os.path.dirname(os.path.abspath(__file__))
COVER = os.path.join(WORK_DIR, "cover_private.jpg")

SUBSCRIPTIONS_URL = "https://raw.githubusercontent.com/kort0881/vpn-checker-backend/refs/heads/main/checked/subscriptions_list.txt"
PROXIES_URL = "https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/verified/proxy_all_tme_verified.txt"
KEYS_PER_CHUNK = 100


def parse_categories(text: str) -> Dict[str, List[str]]:
    categories = {}
    current_category = None
    for line in text.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        cat_match = re.match(r"===\s*(.+?)\s*===", line)
        if cat_match:
            current_category = cat_match.group(1).strip()
            categories[current_category] = []
            continue
        if line.startswith("http") and ".txt" in line and current_category:
            categories[current_category].append(line)
    return categories


def categorize_key_category(cat_name: str) -> str:
    name = cat_name.lower()
    if "europe" in name or "euro" in name or "🇪🇺" in name:
        if "fast" in name or "white" in name:
            return "EU_FAST"
        return "EU_ALL"
    if "russia" in name or "ru_" in name or "🇷🇺" in name:
        if "fast" in name or "white" in name:
            return "RU_FAST"
        return "RU_ALL"
    return "OTHER"


def get_category_priority(group: str) -> int:
    return {"EU_FAST": 1, "RU_FAST": 2, "EU_ALL": 3, "RU_ALL": 4, "OTHER": 5}.get(group, 6)


def fetch_keys_from_url(url: str) -> List[str]:
    try:
        resp = robust_session.get(url, timeout=30)
        if resp.status_code != 200:
            return []
        keys = []
        for line in resp.text.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if any(line.startswith(p) for p in ["vless://", "vmess://", "trojan://", "ss://", "ssr://"]):
                keys.append(line)
        return keys
    except Exception:
        return []


def load_all_keys() -> List[Tuple[str, str]]:
    print("📥 Загрузка subscriptions_list.txt...")
    try:
        resp = robust_session.get(SUBSCRIPTIONS_URL, timeout=30)
        if resp.status_code != 200:
            print(f"❌ HTTP {resp.status_code}")
            return []
    except Exception as e:
        print(f"❌ {e}")
        return []

    categories = parse_categories(resp.text)
    print(f"\n📂 Найдено категорий: {len(categories)}")
    for cat, urls in categories.items():
        print(f"   {cat}: {len(urls)} файлов")

    cat_list = sorted(categories.items(), key=lambda x: get_category_priority(categorize_key_category(x[0])))
    all_keys = []
    seen = set()

    for cat_name, urls in cat_list:
        group = categorize_key_category(cat_name)
        print(f"\n📥 {cat_name} (группа: {group})...")
        for url in urls:
            keys = fetch_keys_from_url(url)
            filename = url.split("/")[-1].split("?")[0]
            new_count = 0
            for key in keys:
                if key not in seen:
                    seen.add(key)
                    all_keys.append((key, group))
                    new_count += 1
            print(f"   {filename}: {len(keys)} загружено, {new_count} новых")

    print(f"\n✅ Всего уникальных ключей: {len(all_keys)}")
    return all_keys


def chunk_keys(keys: List[Tuple[str, str]]) -> List[List[Tuple[str, str]]]:
    return [keys[i:i + KEYS_PER_CHUNK] for i in range(0, len(keys), KEYS_PER_CHUNK)]


def load_active_proxies(limit=10):
    try:
        resp = robust_session.get(PROXIES_URL, timeout=30)
        if resp.status_code != 200:
            return []
        proxies = []
        for line in resp.text.strip().split("\n"):
            line = line.strip()
            if line and not line.startswith("#"):
                proxies.append(line)
                if len(proxies) >= limit:
                    break
        return proxies
    except Exception:
        return []


def send_photo(channel_id, photo_path, caption="", bot_token=None):
    url = f"https://api.telegram.org/bot{bot_token}"
    if DRY_RUN:
        print(f"\n[DRY_RUN] sendPhoto -> {channel_id}")
        return None
    try:
        with open(photo_path, "rb") as photo:
            r = robust_session.post(
                f"{url}/sendPhoto",
                data={"chat_id": channel_id, "caption": caption, "parse_mode": "HTML"},
                files={"photo": photo},
                timeout=60,
            )
            return r.json()
    except Exception as e:
        print(f"❌ Ошибка фото: {e}")
        return None


def send_message(channel_id, text, bot_token, reply_markup=None):
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    if DRY_RUN:
        print(f"\n[DRY_RUN] sendMessage -> {channel_id}")
        return {"ok": True}
    try:
        payload = {
            "chat_id": channel_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        if reply_markup:
            payload["reply_markup"] = reply_markup
        r = robust_session.post(url, json=payload, timeout=30)
        return r.json()
    except Exception as e:
        print(f"❌ Ошибка сообщения: {e}")
        return None


def build_keyboard(keys: List[Tuple[str, str]], offset: int) -> dict:
    keyboard = []
    row = []
    for i, (key, group) in enumerate(keys, start=offset + 1):
        row.append({"text": f"🔑 {i}", "copy_text": {"text": key}})
        if len(row) == 2:
            keyboard.append(row)
            row = []
    if row:
        keyboard.append(row)
    return {"inline_keyboard": keyboard}


def main():
    if not BOT_TOKEN or not CHANNEL_ID:
        print("❌ Не установлены TELEGRAM_BOT_TOKEN или TELEGRAM_PRIVATE_CHANNEL")
        return 1

    print("\n" + "=" * 70)
    print(" " * 20 + "📤 PRIVATE TELEGRAM POSTER v2")
    print("=" * 70 + "\n")

    if DRY_RUN:
        print("⚙️ Режим DRY_RUN\n")

    all_keys = load_all_keys()
    if not all_keys:
        print("❌ Нет ключей")
        return 1

    total = len(all_keys)
    chunks = chunk_keys(all_keys)
    print(f"\n📦 Всего: {total} ключей")
    print(f"📨 Чанков по {KEYS_PER_CHUNK}: {len(chunks)}")

    proxies = load_active_proxies(limit=10)
    proxies_keyboard = None
    if proxies:
        keyboard = []
        row = []
        for i, p in enumerate(proxies, start=1):
            row.append({"text": f"📡 Прокси {i}", "copy_text": {"text": p}})
            if len(row) == 2:
                keyboard.append(row)
                row = []
        if row:
            keyboard.append(row)
        proxies_keyboard = {"inline_keyboard": keyboard}

    print(f"\n🔒 Канал: {CHANNEL_ID}\n")

    caption = (
        f"🔐 <b>VPN-ключи</b>\n\n"
        f"📅 <code>{datetime.now().strftime('%Y-%m-%d %H:%M')}</code>\n"
        f"📊 Всего: <b>{total}</b> ключей\n"
        f"📨 Сообщений: <b>{len(chunks)}</b>\n\n"
        f"📡 VLESS | VMess | Trojan | SS"
    )
    if os.path.exists(COVER):
        send_photo(CHANNEL_ID, COVER, caption, BOT_TOKEN)
    else:
        send_message(CHANNEL_ID, caption, BOT_TOKEN)

    time.sleep(1)

    global_offset = 0
    for idx, chunk in enumerate(chunks):
        groups = set(g for _, g in chunk)
        if "EU_FAST" in groups:
            emoji = "🇪🇺⚡"
        elif "RU_FAST" in groups:
            emoji = "🇷🇺⚡"
        elif "EU_ALL" in groups:
            emoji = "🇪🇺"
        elif "RU_ALL" in groups:
            emoji = "🇷🇺"
        else:
            emoji = "🌍"

        chunk_start = global_offset + 1
        chunk_end = global_offset + len(chunk)
        text = f"{emoji} <b>Ключи {chunk_start}-{chunk_end}</b>\nНажми на кнопку — ключ скопируется в буфер."
        keyboard = build_keyboard(chunk, global_offset)
        send_message(CHANNEL_ID, text, BOT_TOKEN, keyboard)
        global_offset += len(chunk)
        time.sleep(0.5)

    if proxies_keyboard:
        send_message(
            CHANNEL_ID,
            "📡 <b>Активные прокси для Telegram</b>",
            BOT_TOKEN,
            proxies_keyboard,
        )

    print("\n✅ Готово")
    return 0


if __name__ == "__main__":
    sys.exit(main())
