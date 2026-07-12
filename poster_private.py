#!/usr/bin/env python3
"""
PRIVATE VPN POSTER — исправленная версия:
- регион определяется ДО замены домена
- TCP-проверка ДО замены
- замена выполняется только перед записью в файлы
"""
import os, sys, re, time, socket, tempfile, shutil, subprocess
from datetime import datetime
from collections import OrderedDict
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ── Конфигурация ────────────────────────────────────────────
SOURCE_URL = (
    "https://raw.githubusercontent.com/kort0881/"
    "vpn-vless-configs-russia/refs/heads/main/data/githubmirror/new/all_new.txt"
)
REPLACE_HOST = "dostyp_k_internety"
TCP_TIMEOUT = 5.0
CHUNK_SIZE = 100
REPO_OWNER = "kort0881"
REPO_NAME = "vpn-private-poster"
BRANCH = "main"
CHECKED_DIR = "checked"

# Маппинг TLD → регион (для исходных доменов)
TLD_REGION = {
    "de": "Europe", "fr": "Europe", "nl": "Europe", "uk": "Europe",
    "it": "Europe", "es": "Europe", "se": "Europe", "no": "Europe",
    "fi": "Europe", "pl": "Europe", "cz": "Europe", "at": "Europe",
    "ch": "Europe", "be": "Europe", "dk": "Europe", "ie": "Europe",
    "pt": "Europe", "gr": "Europe", "hu": "Europe", "ro": "Europe",
    "jp": "Asia", "sg": "Asia", "cn": "Asia", "hk": "Asia",
    "kr": "Asia", "in": "Asia", "tw": "Asia", "my": "Asia",
    "th": "Asia", "vn": "Asia", "ph": "Asia", "id": "Asia",
    "us": "USA", "usa": "USA",
    "ru": "Russia",
}

REGION_ORDER = ["Europe", "Asia", "USA", "Russia", "Other"]

# ── Сессия ───────────────────────────────────────────────────
_sess = requests.Session()
_r = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
_sess.mount("http://", HTTPAdapter(max_retries=_r))
_sess.mount("https://", HTTPAdapter(max_retries=_r))

# ── Конфигурация из env ─────────────────────────────────────
DRY = os.environ.get("TELEGRAM_DRY_RUN", "0") == "1"
BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
CHANNEL_ID = os.environ.get("TELEGRAM_PRIVATE_CHANNEL")
GH_TOKEN = os.environ.get("GH_TOKEN", os.environ.get("GITHUB_TOKEN", ""))
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
COVER_PATH = os.path.join(SCRIPT_DIR, "cover_private.jpg")


# ═══════════════════════════════════════════════════════════════
#  1. Загрузка и очистка (БЕЗ замены домена)
# ═══════════════════════════════════════════════════════════════

def fetch_raw_keys(url):
    """Загрузка сырых строк из источника."""
    print(f"\n📥 Загрузка ключей из {url}...")
    try:
        r = _sess.get(url, timeout=30)
        r.raise_for_status()
    except Exception as e:
        print(f"❌ Ошибка загрузки: {e}")
        return []
    lines = r.text.strip().split("\n")
    print(f"✅ Загружено {len(lines)} строк")
    return lines


def clean_key(raw):
    """Очистка строки: обрезка, удаление хвостов (пробел, #, |, таб)."""
    k = raw.strip()
    k = re.split(r"[ \t#|]", k, maxsplit=1)[0].strip()
    return k


def is_probably_key(line):
    protocols = ("vless://", "vmess://", "trojan://", "ss://", "ssr://")
    return any(line.startswith(p) for p in protocols)


def load_and_clean():
    """Загрузка, очистка, дедупликация (без замены домена)."""
    raw = fetch_raw_keys(SOURCE_URL)
    if not raw:
        return []

    seen = OrderedDict()
    for line in raw:
        k = clean_key(line)
        if not k or not is_probably_key(k):
            continue
        if k in seen:
            continue
        seen[k] = True

    keys = list(seen.keys())
    print(f"✅ После очистки и дедупликации: {len(keys)} уникальных ключей")
    return keys


# ═══════════════════════════════════════════════════════════════
#  2. Вспомогательные функции для работы с ключами
# ═══════════════════════════════════════════════════════════════

def extract_host_port(key):
    """Извлечение хоста и порта из ключа (по исходному формату)."""
    try:
        parsed = urlparse(key)
        host = parsed.hostname
        port = parsed.port
        if host and port:
            return host, port
    except Exception:
        pass

    # @host:port
    m = re.search(r"@([^:]+):(\d+)", key)
    if m:
        return m.group(1), int(m.group(2))

    # server= или add=
    m = re.search(r"(?:server|add)=([^&:]+)(?::(\d+))?", key)
    if m:
        host = m.group(1)
        port = int(m.group(2)) if m.group(2) else 443
        return host, port

    return None, None


def replace_hosts_in_key(key, new_host):
    """Замена всех вхождений хостов на единый адрес (для финальных файлов)."""
    key = re.sub(r"@([^:@\s]+)", f"@{new_host}", key)
    key = re.sub(r"(server|add)=([^&\s]+)", rf"\1={new_host}", key)
    return key


def get_region_from_key(key):
    """Определение региона по TLD хоста (исходный ключ)."""
    host, _ = extract_host_port(key)
    if not host:
        return "Other"
    parts = host.lower().split(".")
    if len(parts) >= 2:
        tld = parts[-1]
        return TLD_REGION.get(tld, "Other")
    return "Other"


# ═══════════════════════════════════════════════════════════════
#  3. TCP-проверка
# ═══════════════════════════════════════════════════════════════

def tcp_check(host, port, timeout=TCP_TIMEOUT):
    try:
        ip = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        start = time.time()
        sock.connect((ip[0][4][0], port))
        elapsed = time.time() - start
        sock.close()
        return round(elapsed, 3)
    except Exception:
        return None


def check_keys(keys):
    """Прогон TCP-проверки по исходным ключам."""
    total = len(keys)
    working = []   # (key_original, rtt, region)
    print(f"\n🔍 Проверка ключей (TCP ping, таймаут {TCP_TIMEOUT} сек)...")
    for idx, key in enumerate(keys, 1):
        host, port = extract_host_port(key)
        if not host or not port:
            print(f"  [{idx}/{total}] ⚠️ не удалось извлечь хост/порт, пропущен")
            continue
        rtt = tcp_check(host, port)
        if rtt is not None:
            region = get_region_from_key(key)
            working.append((key, rtt, region))
            rtt_ms = round(rtt * 1000, 1)
            print(f"  [{idx}/{total}] ✅ {rtt_ms} мс ({region})")
        else:
            print(f"  [{idx}/{total}] ❌ не работает")
    print(f"\n✅ Рабочих ключей: {len(working)} из {total}")
    return working


# ═══════════════════════════════════════════════════════════════
#  4. Группировка и сортировка
# ═══════════════════════════════════════════════════════════════

def group_and_sort(working):
    """
    working: list of (key_original, rtt, region)
    Возвращает OrderedDict: {region: [(key_original, rtt), ...]}
    Уже отсортировано по RTT внутри группы.
    """
    groups = OrderedDict()
    for r in REGION_ORDER:
        groups[r] = []

    for key, rtt, region in working:
        if region not in groups:
            region = "Other"
        groups[region].append((key, rtt))

    for region in groups:
        groups[region].sort(key=lambda x: x[1])

    print("\n📊 По регионам:")
    for region in REGION_ORDER:
        cnt = len(groups[region])
        print(f"  {region}: {cnt} ключей")
        if cnt > 0:
            fastest = round(groups[region][0][1] * 1000, 1)
            slowest = round(groups[region][-1][1] * 1000, 1)
            print(f"    🏁 {fastest} мс ... {slowest} мс")

    return groups


# ═══════════════════════════════════════════════════════════════
#  5. Создание файлов с ЗАМЕНЁННЫМИ ключами
# ═══════════════════════════════════════════════════════════════

def chunk_list(lst, size):
    return [lst[i:i+size] for i in range(0, len(lst), size)]


def create_subscription_files(groups, output_dir):
    """
    Принимает groups: {region: [(key_original, rtt), ...]}
    Заменяет домен в каждом ключе, разбивает на чанки, создаёт файлы.
    """
    os.makedirs(output_dir, exist_ok=True)
    file_meta = []

    for region in REGION_ORDER:
        items = groups.get(region, [])
        if not items:
            continue
        # Заменяем домен в каждом ключе перед записью
        original_keys = [k for k, _ in items]
        replaced_keys = [replace_hosts_in_key(k, REPLACE_HOST) for k in original_keys]

        chunks = chunk_list(replaced_keys, CHUNK_SIZE)
        for part_num, chunk in enumerate(chunks, 1):
            fname = f"{region}_part{part_num}_sub.txt"
            fpath = os.path.join(output_dir, fname)
            with open(fpath, "w", encoding="utf-8") as f:
                f.write("\n".join(chunk) + "\n" if chunk else "")
            file_meta.append((fname, region, part_num, len(chunk)))

    print(f"\n✅ Создано файлов подписок: {len(file_meta)}")
    for fname, region, part, cnt in file_meta:
        print(f"   {fname} ({cnt} ключей) — {region} (part {part})")

    return file_meta


# ═══════════════════════════════════════════════════════════════
#  6. Git: клонирование + пуш в checked/
# ═══════════════════════════════════════════════════════════════

def push_to_repo(local_dir, file_meta):
    repo_url = f"https://kort0881:{GH_TOKEN}@github.com/{REPO_OWNER}/{REPO_NAME}.git"
    print(f"\n📦 Клонирование {REPO_OWNER}/{REPO_NAME}...")
    clone_dir = os.path.join(local_dir, "repo_clone")
    if os.path.exists(clone_dir):
        shutil.rmtree(clone_dir)

    result = subprocess.run(
        ["git", "clone", repo_url, clone_dir, "--depth=1"],
        capture_output=True, text=True, timeout=60
    )
    if result.returncode != 0:
        print(f"❌ Ошибка клонирования: {result.stderr.strip()}")
        return False

    checked_path = os.path.join(clone_dir, CHECKED_DIR)
    os.makedirs(checked_path, exist_ok=True)

    for fname, _, _, _ in file_meta:
        src = os.path.join(local_dir, fname)
        dst = os.path.join(checked_path, fname)
        shutil.copy2(src, dst)

    subprocess.run(["git", "add", "-A"], cwd=clone_dir, capture_output=True, timeout=30)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
    commit_result = subprocess.run(
        ["git", "commit", "-m", f"Auto update subscription files — {ts}"],
        cwd=clone_dir, capture_output=True, text=True, timeout=30
    )

    if commit_result.returncode != 0 and "nothing to commit" not in commit_result.stderr:
        print(f"❌ Ошибка коммита: {commit_result.stderr.strip()}")
        return False

    if "nothing to commit" in commit_result.stderr:
        print("ℹ️  Нет изменений для пуша.")
        return True

    print("📤 Пуш в репозиторий...")
    push_result = subprocess.run(
        ["git", "push", "origin", BRANCH],
        cwd=clone_dir, capture_output=True, text=True, timeout=60
    )
    if push_result.returncode != 0:
        print(f"❌ Ошибка пуша: {push_result.stderr.strip()}")
        return False

    print(f"✅ Успешно запушено {len(file_meta)} файлов в {CHECKED_DIR}/")
    return True


# ═══════════════════════════════════════════════════════════════
#  7. Telegram: отправка
# ═══════════════════════════════════════════════════════════════

def send_photo(chat_id, photo_path, caption, bot_token):
    if DRY:
        print(f"[DRY] Отправка фото: {photo_path}")
        return True
    try:
        with open(photo_path, "rb") as ph:
            r = _sess.post(
                f"https://api.telegram.org/bot{bot_token}/sendPhoto",
                data={"chat_id": chat_id, "caption": caption, "parse_mode": "HTML"},
                files={"photo": ph},
                timeout=60,
            )
        j = r.json()
        if not j.get("ok"):
            print(f"❌ Ошибка фото: {j.get('description')}")
            return False
        return True
    except Exception as e:
        print(f"❌ Ошибка отправки фото: {e}")
        return False


def send_message(chat_id, text, bot_token, reply_markup=None):
    if DRY:
        print(f"[DRY] Сообщение: {text[:60]}...")
        return True
    try:
        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        if reply_markup:
            payload["reply_markup"] = reply_markup
        r = _sess.post(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            json=payload,
            timeout=30,
        )
        j = r.json()
        if not j.get("ok"):
            print(f"❌ Ошибка сообщения: {j.get('description')}")
            return False
        return True
    except Exception as e:
        print(f"❌ Ошибка отправки сообщения: {e}")
        return False


def build_keyboard(file_meta):
    kb_rows = []
    current_row = []
    for fname, region, part_num, _ in file_meta:
        url = (
            f"https://raw.githubusercontent.com/"
            f"{REPO_OWNER}/{REPO_NAME}/{BRANCH}/{CHECKED_DIR}/{fname}"
        )
        label = f"📥 {region} (part {part_num})"
        if len(label) > 32:
            label = label[:29] + ".."
        current_row.append({"text": label, "url": url})
        if len(current_row) == 2:
            kb_rows.append(current_row)
            current_row = []
    if current_row:
        kb_rows.append(current_row)
    return {"inline_keyboard": kb_rows}


def send_telegram(file_meta, total_keys):
    if not BOT_TOKEN or not CHANNEL_ID:
        print("⚠️  TELEGRAM_BOT_TOKEN или TELEGRAM_PRIVATE_CHANNEL не заданы")
        return False

    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    caption = (
        f"🔐 <b>Private VPN Subscriptions</b>\n"
        f"📅 {ts}\n"
        f"📊 Всего ключей: {total_keys}\n"
        f"📁 Файлов: {len(file_meta)}"
    )

    time.sleep(1)
    if os.path.exists(COVER_PATH):
        ok = send_photo(CHANNEL_ID, COVER_PATH, caption, BOT_TOKEN)
        print(f"📸 Обложка отправлена: {ok}")
    else:
        ok = send_message(CHANNEL_ID, caption, BOT_TOKEN)
        print(f"📝 Сообщение-обложка отправлено: {ok}")

    keyboard = build_keyboard(file_meta)
    all_buttons = keyboard["inline_keyboard"]
    max_buttons_per_msg = 100
    button_batches = []
    current_batch = []
    button_count = 0

    for row in all_buttons:
        current_batch.append(row)
        button_count += len(row)
        if button_count >= max_buttons_per_msg:
            button_batches.append(current_batch)
            current_batch = []
            button_count = 0
    if current_batch:
        button_batches.append(current_batch)

    for idx, batch in enumerate(button_batches):
        time.sleep(1.5)
        header = (
            f"📋 Файлы подписок (часть {idx+1}/{len(button_batches)})"
            if len(button_batches) > 1
            else "📋 Файлы подписок"
        )
        markup = {"inline_keyboard": batch}
        ok = send_message(CHANNEL_ID, header, BOT_TOKEN, markup)
        print(f"📨 Кнопки (batch {idx+1}) отправлены: {ok}")

    return True


# ═══════════════════════════════════════════════════════════════
#  8. Main
# ═══════════════════════════════════════════════════════════════

def main():
    version = "PRIVATE POSTER v24 (FIXED: region before replace, TCP before replace)"
    print(f"\n{'='*50}")
    print(f"{version} (DRY RUN = {'ON' if DRY else 'OFF'})")
    if DRY:
        print("    no posts, no pushes")
    print(f"{'='*50}\n")

    # 1. Загрузка и очистка (без замены)
    keys = load_and_clean()
    if not keys:
        print("❌ Нет ключей для обработки")
        return 1

    # 2. TCP-проверка (по исходным ключам)
    working = check_keys(keys)
    if not working:
        print("❌ Нет рабочих ключей")
        return 1

    # 3. Группировка и сортировка по регионам
    groups = group_and_sort(working)

    # 4. Создание файлов (замена домена происходит внутри)
    with tempfile.TemporaryDirectory(prefix="vpn_poster_") as tmpdir:
        file_meta = create_subscription_files(groups, tmpdir)

        if not file_meta:
            print("❌ Нет файлов для публикации")
            return 1

        # 5. Пуш на GitHub (если не DRY)
        if DRY:
            print(f"\n[DRY] Пропускаем клонирование и пуш. Файлы во временной папке {tmpdir}")
        else:
            if not GH_TOKEN:
                print("⚠️  GH_TOKEN не задан — пуш невозможен")
                return 1
            push_ok = push_to_repo(tmpdir, file_meta)
            if not push_ok:
                print("❌ Ошибка пуша в репозиторий")
                return 1

        # 6. Telegram (если не DRY)
        total_keys = sum(cnt for _, _, _, cnt in file_meta)
        if DRY:
            print(f"\n[DRY] Пропускаем отправку в Telegram.")
        else:
            tg_ok = send_telegram(file_meta, total_keys)
            if not tg_ok:
                print("❌ Ошибка отправки в Telegram")
                return 1

    print("\n✅ Готово!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
