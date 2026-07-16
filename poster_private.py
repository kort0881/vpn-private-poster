#!/usr/bin/env python3
"""
PRIVATE VPN POSTER — v25 + fix &amp; + convert ss:// (with UUID) to vless://
"""
import os, sys, re, time, socket, tempfile, shutil, subprocess
from datetime import datetime
from collections import OrderedDict
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ── Конфигурация ────────────────────────────────────────────
SOURCE_URL = (
    "https://raw.githubusercontent.com/kort0881/"
    "vpn-vless-configs-russia/refs/heads/main/data/githubmirror/new/all_new.txt"
)
REPLACE_HOST = "dostyp_k_internety"
TCP_TIMEOUT = 2.0
MAX_KEYS_TO_CHECK = 200
MAX_WORKERS = 30
CHUNK_SIZE = 100
REPO_OWNER = "kort0881"
REPO_NAME = "vpn-private-poster"
BRANCH = "main"
CHECKED_DIR = "checked"

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

_sess = requests.Session()
_r = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
_sess.mount("http://", HTTPAdapter(max_retries=_r))
_sess.mount("https://", HTTPAdapter(max_retries=_r))

DRY = os.environ.get("TELEGRAM_DRY_RUN", "0") == "1"
BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
CHANNEL_ID = os.environ.get("TELEGRAM_PRIVATE_CHANNEL")
GH_TOKEN = os.environ.get("GH_TOKEN", os.environ.get("GITHUB_TOKEN", ""))
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
COVER_PATH = os.path.join(SCRIPT_DIR, "cover_private.jpg")


def fetch_raw_keys(url):
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
    k = raw.strip()
    k = re.split(r"[ \t#|]", k, maxsplit=1)[0].strip()
    k = k.replace("&amp;", "&")   # фикс &amp;
    # Если ключ ss:// и содержит UUID (длина > 50), преобразуем в vless://
    if k.startswith("ss://") and len(k) > 50:
        k = "vless://" + k[5:]
    return k


def is_probably_key(line):
    protocols = ("vless://", "vmess://", "trojan://", "ss://", "ssr://")
    return any(line.startswith(p) for p in protocols)


def load_and_clean():
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
    if len(keys) > MAX_KEYS_TO_CHECK:
        print(f"⚠️  Слишком много ключей ({len(keys)}), проверяем только {MAX_KEYS_TO_CHECK}")
        keys = keys[:MAX_KEYS_TO_CHECK]
    print(f"✅ После очистки и дедупликации: {len(keys)} уникальных ключей")
    return keys


def extract_host_port(key):
    try:
        parsed = urlparse(key)
        host = parsed.hostname
        port = parsed.port
        if host and port:
            return host, port
    except Exception:
        pass

    m = re.search(r"@([^:]+):(\d+)", key)
    if m:
        return m.group(1), int(m.group(2))

    m = re.search(r"(?:server|add)=([^&:]+)(?::(\d+))?", key)
    if m:
        host = m.group(1)
        port = int(m.group(2)) if m.group(2) else 443
        return host, port

    return None, None


def replace_hosts_in_key(key, new_host):
    key = re.sub(r"@([^:@\s]+)", f"@{new_host}", key)
    key = re.sub(r"(server|add)=([^&\s]+)", rf"\1={new_host}", key)
    return key


def get_region_from_key(key):
    host, _ = extract_host_port(key)
    if not host:
        return "Other"
    parts = host.lower().split(".")
    if len(parts) >= 2:
        tld = parts[-1]
        return TLD_REGION.get(tld, "Other")
    return "Other"


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


def check_key_worker(key):
    host, port = extract_host_port(key)
    if not host or not port:
        return None
    rtt = tcp_check(host, port)
    if rtt is not None:
        region = get_region_from_key(key)
        return (key, rtt, region)
    return None


def check_keys_parallel(keys):
    total = len(keys)
    working = []
    print(f"\n🔍 Проверка ключей (параллельно, {MAX_WORKERS} потоков, таймаут {TCP_TIMEOUT} сек)...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(check_key_worker, key): idx for idx, key in enumerate(keys, 1)}
        for future in as_completed(futures):
            idx = futures[future]
            result = future.result()
            if result:
                working.append(result)
                rtt_ms = round(result[1] * 1000, 1)
                print(f"  [{idx}/{total}] ✅ {rtt_ms} мс ({result[2]})")
            else:
                print(f"  [{idx}/{total}] ❌ не работает")
    print(f"\n✅ Рабочих ключей: {len(working)} из {total}")
    return working


def group_and_sort(working):
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


def chunk_list(lst, size):
    return [lst[i:i+size] for i in range(0, len(lst), size)]


def create_subscription_files(groups, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    file_meta = []

    for region in REGION_ORDER:
        items = groups.get(region, [])
        if not items:
            continue
        original_keys = [k for k, _ in items]
        # Заменяем хост (и при необходимости уже преобразованные vless)
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
    
    subprocess.run(
        ["git", "config", "user.name", "GitHub Actions Bot"],
        cwd=clone_dir, capture_output=True, timeout=10
    )
    subprocess.run(
        ["git", "config", "user.email", "actions@github.com"],
        cwd=clone_dir, capture_output=True, timeout=10
    )
    
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
        if "rejected" in push_result.stderr:
            print("🔄 Конфликт, пробуем pull --rebase...")
            pull_result = subprocess.run(
                ["git", "pull", "--rebase", "origin", BRANCH],
                cwd=clone_dir, capture_output=True, text=True, timeout=30
            )
            if pull_result.returncode != 0:
                print(f"❌ Ошибка rebase: {pull_result.stderr.strip()}")
                return False
            push_result = subprocess.run(
                ["git", "push", "origin", BRANCH],
                cwd=clone_dir, capture_output=True, text=True, timeout=60
            )
            if push_result.returncode != 0:
                print(f"❌ Ошибка пуша: {push_result.stderr.strip()}")
                return False
        else:
            print(f"❌ Ошибка пуша: {push_result.stderr.strip()}")
            return False

    print(f"✅ Успешно запушено {len(file_meta)} файлов в {CHECKED_DIR}/")
    return True


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


def main():
    version = "PRIVATE POSTER v25-fix (ss://→vless for UUID keys)"
    print(f"\n{'='*50}")
    print(f"{version} (DRY RUN = {'ON' if DRY else 'OFF'})")
    if DRY:
        print("    no posts, no pushes")
    print(f"{'='*50}\n")

    keys = load_and_clean()
    if not keys:
        print("❌ Нет ключей для обработки")
        return 1

    working = check_keys_parallel(keys)
    if not working:
        print("❌ Нет рабочих ключей")
        return 1

    groups = group_and_sort(working)

    with tempfile.TemporaryDirectory(prefix="vpn_poster_") as tmpdir:
        file_meta = create_subscription_files(groups, tmpdir)

        if not file_meta:
            print("❌ Нет файлов для публикации")
            return 1

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
