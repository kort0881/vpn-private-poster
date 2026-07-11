#!/usr/bin/env python3
"""
Private VPN Keys Telegram Poster.
Публикует VPN-ключи в приватный Telegram-канал каждые 2 часа.

Использует:
- results/premium/ (elite.txt, premium.txt, good.txt) — основные ключи
- checked/latest/verified.txt — fallback
- cover_private.jpg — обложка
- GitHub API для списка подписок
- Telegram Proxy Collector для списка прокси
"""
import os
import sys
import requests
import base64
from datetime import datetime
import urllib.parse
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
PREMIUM_FOLDER = os.path.join(RESULTS_FOLDER, "premium")
LIGHT_VERIFIED = os.path.join(WORK_DIR, "checked", "latest", "verified.txt")
COVER = os.path.join(WORK_DIR, "cover_private.jpg")


# --- ВСПОМОГАТЕЛЬНЫЕ ---
def clean_key(k: str) -> str:
    k = k.strip()
    if " " in k:
        k = k.split(" ")[0]
    return k


def fix_universal(key: str) -> str:
    key = key.strip()
    if not key.startswith("vless://") or "type=xhttp" not in key:
        return key
    try:
        parsed = urllib.parse.urlparse(key)
        query = urllib.parse.parse_qs(parsed.query)
        if query.get("type", [""])[0].lower() == "xhttp":
            query["type"] = ["http"]
        new_query = urllib.parse.urlencode(query, doseq=True)
        return urllib.parse.urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment,
        ))
    except Exception:
        return key


# --- ЗАГРУЗКА КЛЮЧЕЙ ---
def load_premium_keys():
    all_keys = []
    stats = {"elite": 0, "premium": 0, "good": 0}
    for filename, category in [("elite.txt", "elite"), ("premium.txt", "premium"), ("good.txt", "good")]:
        filepath = os.path.join(PREMIUM_FOLDER, filename)
        if not os.path.exists(filepath):
            print(f"  ⚠️ {filename} не найден")
            continue
        count = 0
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    key = fix_universal(clean_key(line))
                    if key:
                        all_keys.append(key)
                        count += 1
        stats[category] = count
        print(f"  ✅ {filename}: {count} ключей")
    return all_keys, stats


def load_fallback_keys():
    verified = [f for f in os.listdir(RESULTS_FOLDER) if f.startswith("verified_") and f.endswith(".txt")]
    semi_dead = [f for f in os.listdir(RESULTS_FOLDER) if f.startswith("semi_dead_") and f.endswith(".txt")]
    if verified:
        latest = max(verified, key=lambda f: os.path.getmtime(os.path.join(RESULTS_FOLDER, f)))
        source = "verified"
    elif semi_dead:
        latest = max(semi_dead, key=lambda f: os.path.getmtime(os.path.join(RESULTS_FOLDER, f)))
        source = "semi_dead"
    else:
        return [], None, None
    filepath = os.path.join(RESULTS_FOLDER, latest)
    keys = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                key = fix_universal(clean_key(line))
                if key:
                    keys.append(key)
    return keys, latest, source


def load_light_verified_keys():
    if not os.path.exists(LIGHT_VERIFIED):
        return []
    keys = []
    with open(LIGHT_VERIFIED, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                key = fix_universal(clean_key(line))
                if key:
                    keys.append(key)
    return keys


# --- ФАЙЛЫ ---
def create_private_file(all_keys):
    date_str = datetime.now().strftime("%Y%m%d_%H%M")
    filepath = os.path.join(RESULTS_FOLDER, f"private_all_{date_str}.txt")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}\n")
        f.write("# Verified: Triple-check (TCP + XRAY + Categories)\n")
        f.write(f"# Keys in file: {len(all_keys)}\n\n")
        for key in all_keys:
            f.write(key + "\n")
    return filepath, len(all_keys)


def safe_remove(filepath: str):
    try:
        if os.path.exists(filepath):
            os.remove(filepath)
    except OSError as e:
        print(f"⚠️ Не удалось удалить {filepath}: {e}")


# --- ПОДПИСКИ ---
def load_subscriptions():
    url = "https://api.github.com/repos/kort0881/vpn-checker-backend/contents/checked/subscriptions_list.txt"
    try:
        resp = robust_session.get(url, timeout=15)
        if resp.status_code != 200:
            print(f"⚠️ Не удалось получить подписки: HTTP {resp.status_code}")
            return None
        data = resp.json()
        content = base64.b64decode(data["content"]).decode("utf-8")
        if not content.strip():
            return None
        return content
    except Exception as e:
        print(f"❌ Ошибка загрузки подписок: {e}")
        return None


def parse_subscriptions_for_buttons(subscriptions_text):
    if not subscriptions_text:
        return []
    lines = subscriptions_text.strip().split("\n")
    buttons = []
    in_black = False
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith("==="):
            in_black = "BLACK" in line or "⚠️" in line
            continue
        if in_black:
            continue
        if line.startswith("http"):
            filename = line.split("/")[-1].replace(".txt", "")
            btn_text = f"📥 {filename}"[:32]
            buttons.append({"text": btn_text, "url": line})
    return buttons


# --- ПРОКСИ ---
def load_active_proxies(limit=10):
    url = "https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/verified/proxy_all_tme_verified.txt"
    try:
        resp = robust_session.get(url, timeout=30)
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


def build_proxies_keyboard(proxies):
    keyboard = []
    row = []
    for i, proxy in enumerate(proxies, start=1):
        row.append({"text": f"🔑 Прокси {i}", "copy_text": {"text": proxy}})
        if len(row) == 2:
            keyboard.append(row)
            row = []
    if row:
        keyboard.append(row)
    return keyboard


# --- TELEGRAM ---
def send_photo_with_file(channel_id, photo_path, file_path, caption="", bot_token=None):
    url = f"https://api.telegram.org/bot{bot_token}"
    if DRY_RUN:
        print(f"\n[DRY_RUN] sendPhoto + sendDocument -> {channel_id}")
        print(f"Caption:\n{caption}\n")
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
        print(f"\n[DRY_RUN] sendDocument -> {chat_id}\nCaption: {caption}")
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
        print(f"\n[DRY_RUN] sendMessage -> {channel_id}\n{text[:100]}...")
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
        print("❌ Ошибка: не установлены TELEGRAM_BOT_TOKEN или TELEGRAM_PRIVATE_CHANNEL")
        return 1

    print("\n" + "=" * 70)
    print(" " * 20 + "📤 PRIVATE TELEGRAM POSTER")
    print("=" * 70 + "\n")

    if DRY_RUN:
        print("⚙️ Режим DRY_RUN\n")

    if not os.path.exists(RESULTS_FOLDER):
        print(f"❌ Папка {RESULTS_FOLDER} не существует")
        return 1

    # 1. Загрузка ключей
    all_keys = []
    key_stats = None
    source_info = ""

    if os.path.exists(PREMIUM_FOLDER):
        print("📁 Ищем ключи в results/premium/...")
        all_keys, key_stats = load_premium_keys()
        if all_keys:
            source_info = "results/premium (elite + premium + good)"
            print(f"\n✅ Загружено: {len(all_keys)} ключей")
            print(f"   Elite: {key_stats['elite']} | Premium: {key_stats['premium']} | Good: {key_stats['good']}")

    if not all_keys:
        print("\n📁 Premium пусто, ищем verified/semi_dead...")
        all_keys, filename, source = load_fallback_keys()
        if all_keys:
            source_info = f"{source} ({filename})"
            print(f"✅ Fallback: {len(all_keys)} ключей из {filename}")
        else:
            print("⚠️ Ищем checked/latest/verified.txt...")
            all_keys = load_light_verified_keys()
            if all_keys:
                source_info = "checked/latest/verified.txt"
                print(f"✅ Fallback: {len(all_keys)} ключей из verified.txt")

    if not all_keys:
        print("❌ Нет ключей для публикации")
        return 1

    total = len(all_keys)
    print(f"\n📦 Всего: {total} ключей")
    print(f"📂 Источник: {source_info}\n")

    # 2. Подписки и прокси
    subscriptions_raw = load_subscriptions()
    subscriptions_buttons = parse_subscriptions_for_buttons(subscriptions_raw)
    proxies = load_active_proxies(limit=10)
    proxies_keyboard = build_proxies_keyboard(proxies) if proxies else None

    # 3. Пост в канал
    print("\n" + "=" * 70)
    print(f"🔒 Канал: {CHANNEL_ID}")
    print("=" * 70 + "\n")

    if total > 10:
        private_file, private_count = create_private_file(all_keys)
        caption = (
            f"🔐 <b>Полный список ключей</b>\n\n"
            f"📅 <code>{datetime.now().strftime('%Y-%m-%d %H:%M')}</code>\n"
            f"📦 В файле: <b>{private_count}</b> ключей\n"
            f"📊 Всего: <b>{total}</b>\n\n"
            f"📡 VLESS | VMess | Trojan | SS"
        )
        if os.path.exists(COVER):
            send_photo_with_file(CHANNEL_ID, COVER, private_file, caption, BOT_TOKEN)
        else:
            print("⚠️ Нет обложки, отправляю только файл")
            send_document(CHANNEL_ID, private_file, caption, BOT_TOKEN)
        safe_remove(private_file)

    # Кнопки подписок
    if subscriptions_buttons:
        keyboard = []
        row = []
        for btn in subscriptions_buttons:
            row.append({"text": btn["text"], "copy_text": {"text": btn["url"]}})
            if len(row) == 2:
                keyboard.append(row)
                row = []
        if row:
            keyboard.append(row)
        send_message(
            CHANNEL_ID,
            "📋 <b>Ссылки на подписки</b>\n\n🎯 Нажми на кнопку — ссылка скопируется",
            BOT_TOKEN,
            {"inline_keyboard": keyboard},
        )

    # Кнопки прокси
    if proxies_keyboard:
        send_message(
            CHANNEL_ID,
            "📋 <b>Активные прокси для Telegram</b>\n\nНажмите на кнопку, чтобы скопировать ссылку.",
            BOT_TOKEN,
            {"inline_keyboard": proxies_keyboard},
        )

    print("\n✅ Скрипт завершён")
    return 0


if __name__ == "__main__":
    sys.exit(main())
