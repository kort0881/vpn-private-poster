#!/usr/bin/env python3
"""
Private VPN Keys Telegram Poster.
Публикует VPN-ключи в приватный Telegram-канал каждые 2 часа.

Источник ключей: subscriptions_list.txt из vpn-checker-backend.
Первые 20 ключей — кнопки с копированием, остальные в файле.
"""
import os
import sys
import requests
import base64
from datetime import datetime
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# --- УСТОЙЧИВАЯ СЕССИЯ ---
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
RESULTS_FOLDER = os.path.join(WORK_DIR, "results")
COVER = os.path.join(WORK_DIR, "cover_private.jpg")

# Единственный источник ключей
SUBSCRIPTIONS_URL = "https://raw.githubusercontent.com/kort0881/vpn-checker-backend/refs/heads/main/checked/subscriptions_list.txt"
# Прокси
PROXIES_URL = "https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/verified/proxy_all_tme_verified.txt"


# --- ЗАГРУЗКА КЛЮЧЕЙ ---
def fetch_keys_from_url(url: str) -> list:
    """Скачивает файл по URL и извлекает VPN-ключи."""
    try:
        resp = robust_session.get(url, timeout=30)
        if resp.status_code != 200:
            print(f"  ⚠️ HTTP {resp.status_code} — {url.split('/')[-1]}")
            return []
        keys = []
        for line in resp.text.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if any(line.startswith(p) for p in ["vless://", "vmess://", "trojan://", "ss://", "ssr://"]):
                keys.append(line)
        print(f"  ✅ {len(keys)} ключей из {url.split('/')[-1].split('?')[0]}")
        return keys
    except Exception as e:
        print(f"  ❌ {url.split('/')[-1]}: {e}")
        return []


def load_keys() -> list:
    """Загружает список файлов из subscriptions_list.txt, затем скачивает каждый."""
    print("📥 Загрузка списка файлов...")
    try:
        resp = robust_session.get(SUBSCRIPTIONS_URL, timeout=30)
        if resp.status_code != 200:
            print(f"❌ Не удалось загрузить список: HTTP {resp.status_code}")
            return []
    except Exception as e:
        print(f"❌ Ошибка загрузки списка: {e}")
        return []

    # Парсим URL файлов из subscriptions_list.txt
    file_urls = []
    for line in resp.text.strip().split("\n"):
        line = line.strip()
        if line.startswith("http") and ".txt" in line:
            file_urls.append(line)

    print(f"📄 Найдено {len(file_urls)} файлов")
    print("📥 Скачиваю ключи...")

    all_keys = []
    for url in file_urls:
        keys = fetch_keys_from_url(url)
        all_keys.extend(keys)

    # Убираем дубликаты, сохраняем порядок
    seen = set()
    unique_keys = []
    for k in all_keys:
        if k not in seen:
            seen.add(k)
            unique_keys.append(k)

    print(f"\n✅ Всего уникальных ключей: {len(unique_keys)}")
    return unique_keys


# --- ФАЙЛЫ ---
def create_keys_file(all_keys):
    """Создаёт файл с ключами (все, кроме первых 20, которые идут в кнопки)."""
    date_str = datetime.now().strftime("%Y%m%d_%H%M")
    filepath = os.path.join(RESULTS_FOLDER, f"keys_{date_str}.txt")
    os.makedirs(RESULTS_FOLDER, exist_ok=True)
    # Первые 20 не пишем в файл — они в кнопках
    file_keys = all_keys[20:]
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"# VPN Keys — {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}\n")
        f.write(f"# Total: {len(all_keys)} | In file: {len(file_keys)} | In buttons: {len(all_keys[:20])}\n\n")
        for key in file_keys:
            f.write(key + "\n")
    return filepath, len(file_keys)


def safe_remove(filepath: str):
    try:
        if os.path.exists(filepath):
            os.remove(filepath)
    except OSError as e:
        print(f"⚠️ Не удалось удалить {filepath}: {e}")


# --- ПРОКСИ ---
def load_active_proxies(limit=10):
    try:
        resp = robust_session.get(PROXIES_URL, timeout=30)
        if resp.status_code != 200:
            print(f"⚠️ Не удалось загрузить прокси: HTTP {resp.status_code}")
            return []
        proxies = []
        for line in resp.text.strip().split("\n"):
            line = line.strip()
            if line and not line.startswith("#"):
                proxies.append(line)
                if len(proxies) >= limit:
                    break
        print(f"✅ Загружено {len(proxies)} прокси")
        return proxies
    except Exception as e:
        print(f"❌ Ошибка загрузки прокси: {e}")
        return []


# --- TELEGRAM ---
def send_photo_with_file(channel_id, photo_path, file_path, caption="", bot_token=None):
    url = f"https://api.telegram.org/bot{bot_token}"
    if DRY_RUN:
        print(f"\n[DRY_RUN] sendPhoto + sendDocument -> {channel_id}")
        return {"ok": True}
    try:
        with open(photo_path, "rb") as photo:
            r = robust_session.post(
                f"{url}/sendPhoto",
                data={"chat_id": channel_id, "caption": caption, "parse_mode": "HTML"},
                files={"photo": photo},
                timeout=60,
            )
            photo_result = r.json()
        if photo_result.get("ok"):
            msg_id = photo_result["result"]["message_id"]
            with open(file_path, "rb") as doc:
                r = robust_session.post(
                    f"{url}/sendDocument",
                    data={"chat_id": channel_id, "reply_to_message_id": msg_id},
                    files={"document": doc},
                    timeout=120,
                )
                return r.json()
        return photo_result
    except Exception as e:
        print(f"❌ Ошибка отправки: {e}")
        return None


def send_document(chat_id, file_path, caption="", bot_token=None):
    url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
    if DRY_RUN:
        print(f"\n[DRY_RUN] sendDocument -> {chat_id}")
        return {"ok": True}
    try:
        with open(file_path, "rb") as f:
            r = robust_session.post(
                url,
                data={"chat_id": chat_id, "caption": caption, "parse_mode": "HTML"},
                files={"document": f},
                timeout=60,
            )
            return r.json()
    except Exception as e:
        print(f"❌ Ошибка отправки документа: {e}")
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
        print(f"❌ Ошибка отправки сообщения: {e}")
        return None


# --- MAIN ---
def main():
    if not BOT_TOKEN or not CHANNEL_ID:
        print("❌ Не установлены TELEGRAM_BOT_TOKEN или TELEGRAM_PRIVATE_CHANNEL")
        return 1

    print("\n" + "=" * 70)
    print(" " * 20 + "📤 PRIVATE TELEGRAM POSTER")
    print("=" * 70 + "\n")

    if DRY_RUN:
        print("⚙️ Режим DRY_RUN\n")

    # 1. Загружаем ключи
    print("📥 Загрузка ключей...")
    all_keys = load_keys()
    if not all_keys:
        print("❌ Нет ключей для публикации")
        return 1

    total = len(all_keys)
    button_keys = all_keys[:20]
    file_keys = all_keys[20:]

    print(f"📦 Всего: {total} ключей")
    print(f"🔘 В кнопки: {len(button_keys)}")
    print(f"📄 В файл: {len(file_keys)}")

    # 2. Создаём файл с остальными ключами
    private_file, private_count = create_keys_file(all_keys)

    # 3. Загружаем прокси
    proxies = load_active_proxies(limit=10)

    # 4. Формируем клавиатуру с ключами (первые 20)
    keys_keyboard = []
    row = []
    for i, key in enumerate(button_keys, start=1):
        short = key[:40] + ("..." if len(key) > 40 else "")
        row.append({"text": f"🔑 {i}", "copy_text": {"text": key}})
        if len(row) == 2:
            keys_keyboard.append(row)
            row = []
    if row:
        keys_keyboard.append(row)

    # 5. Формируем клавиатуру с прокси
    proxies_keyboard = []
    if proxies:
        row = []
        for i, proxy in enumerate(proxies, start=1):
            row.append({"text": f"📡 Прокси {i}", "copy_text": {"text": proxy}})
            if len(row) == 2:
                proxies_keyboard.append(row)
                row = []
        if row:
            proxies_keyboard.append(row)

    # 6. Отправка
    print("\n" + "=" * 70)
    print(f"🔒 Канал: {CHANNEL_ID}")
    print("=" * 70 + "\n")

    # Пост с обложкой + файлом ключей
    caption = (
        f"🔐 <b>VPN-ключи</b>\n\n"
        f"📅 <code>{datetime.now().strftime('%Y-%m-%d %H:%M')}</code>\n"
        f"📊 Всего: <b>{total}</b> ключей\n"
        f"🔘 В кнопках: <b>{len(button_keys)}</b>\n"
        f"📄 В файле: <b>{private_count}</b>\n\n"
        f"📡 VLESS | VMess | Trojan | SS"
    )

    if os.path.exists(COVER):
        send_photo_with_file(CHANNEL_ID, COVER, private_file, caption, BOT_TOKEN)
    else:
        print("⚠️ Нет обложки, отправляю только файл")
        send_document(CHANNEL_ID, private_file, caption, BOT_TOKEN)

    safe_remove(private_file)

    # Кнопки с ключами (первые 20)
    if keys_keyboard:
        send_message(
            CHANNEL_ID,
            "🔑 <b>Первые 20 ключей</b>\n\nНажми на кнопку — ключ скопируется в буфер.",
            BOT_TOKEN,
            {"inline_keyboard": keys_keyboard},
        )

    # Кнопки с прокси
    if proxies_keyboard:
        send_message(
            CHANNEL_ID,
            "📡 <b>Активные прокси для Telegram</b>\n\nНажми на кнопку — скопируется ссылка.",
            BOT_TOKEN,
            {"inline_keyboard": proxies_keyboard},
        )

    print("\n✅ Скрипт завершён")
    return 0


if __name__ == "__main__":
    sys.exit(main())
