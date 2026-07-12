#!/usr/bin/env python3
"""
PRIVATE VPN POSTER — по ТЗ: TCP-проверка, регионы, файлы в checked/, кнопки-ссылки

Что делает:
  - Загружает ключи из SOURCE_URL (all_new.txt)
  - Очищает мусор, удаляет дубликаты
  - Заменяет домены на единый адрес dostyp_k_internety
  - Проверяет работоспособность TCP-соединением (5 сек таймаут)
  - Группирует по регионам (Europe/Asia/USA/Russia/Other)
  - Сортирует по задержке внутри группы
  - Разбивает на чанки по 100 ключей
  - Создаёт файлы {Регион}_part{N}_sub.txt
  - Пушит в checked/ репозитория
  - Отправляет в Telegram: обложка + кнопки-ссылки на каждый файл
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

# Маппинг TLD → регион
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
#  1. Загрузка и очистка ключей
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
    # Удаляем всё после первого пробела, #, | или табуляции
    k = re.split(r"[ \t#|]", k, maxsplit=1)[0].strip()
    return k


def extract_host_port(key):
    """Извлечение хоста и порта из ключа любого протокола."""
    try:
        parsed = urlparse(key)
        host = parsed.hostname
        port = parsed.port
        if host and port:
            return host, port
    except Exception:
        pass

    # fallback: @host:port
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
    """Замена всех вхождений хостов на единый адрес."""
    # Замена @host:port → @dostyp_k_internety:port
    key = re.sub(r"@([^:@\s]+)", f"@{new_host}", key)
    # Замена server=host → server=new_host, add=host → add=new_host
    key = re.sub(r"(server|add)=([^&\s]+)", rf"\1={new_host}", key)
    return key


def is_probably_key(line):
    """Проверка, похожа ли строка на ключ."""
    protocols = ("vless://", "vmess://", "trojan://", "ss://", "ssr://")
    return any(line.startswith(p) for p in protocols)


def load_and_clean():
    """Полный цикл загрузки, очистки, дедупликации и замены домена."""
    raw = fetch_raw_keys(SOURCE_URL)
    if not raw:
        return []

    seen = OrderedDict()

    for line in raw:
        k = clean_key(line)
        if not k or not is_probably_key(k):
            continue
        # Замена домена
        k = replace_hosts_in_key(k, REPLACE_HOST)
        # Дедупликация с сохранением порядка
        if k in seen:
            continue
        seen[k] = True

    cleaned = list(seen.keys())
    print(f"✅ После очистки и дедупликации: {len(cleaned)} уникальных ключей")
    return cleaned


# ═══════════════════════════════════════════════════════════════
#  2. TCP-проверка
# ═══════════════════════════════════════════════════════════════

def tcp_check(host, port, timeout=TCP_TIMEOUT):
    """TCP-соединение, возвращает задержку в секундах или None."""
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
    """Прогон TCP-проверки по всем ключам."""
    total = len(keys)
    working = []
    print(f"\n🔍 Проверка ключей (TCP ping, таймаут {TCP_TIMEOUT} сек)...")
    for idx, key in enumerate(keys, 1):
        host, port = extract_host_port(key)
        if not host or not port:
            print(f"  [{idx}/{total}] ⚠️  не удалось извлечь хост/порт, пропущен")
            continue
        rtt = tcp_check(host, port)
        if rtt is not None:
            working.append((key, rtt))
            rtt_ms = round(rtt * 1000, 1)
            print(f"  [{idx}/{total}] ✅ {rtt_ms} мс")
        else:
            print(f"  [{idx}/{total}] ❌ не работает")
    print(f"\n✅ Рабочих ключей: {len(working)} из {total}")
    return working


# ═══════════════════════════════════════════════════════════════
#  3. Группировка по регионам
# ═══════════════════════════════════════════════════════════════

def extract_tld(host):
    """Извлечение домена верхнего уровня из хоста."""
    if not host:
        return None
    parts = host.lower().split(".")
    if len(parts) >= 2:
        return parts[-1]
    return None


def get_region(key):
    """Определение региона ключа по TLD хоста."""
    host, _ = extract_host_port(key)
    tld = extract_tld(host)
    if tld:
        return TLD_REGION.get(tld, "Other")
    return "Other"


def group_by_region(keys_with_rtt):
    """
    keys_with_rtt: list of (key, rtt)
    Возвращает OrderedDict: {region: [(key, rtt), ...]}
    Каждая группа отсортирована по возрастанию RTT.
    """
    groups = OrderedDict()
    for r in REGION_ORDER:
        groups[r] = []

    for key, rtt in keys_with_rtt:
        region = get_region(key)
        if region not in groups:
            region = "Other"
        groups[region].append((key, rtt))

    # Сортировка внутри групп по RTT
    for region in groups:
        groups[region].sort(key=lambda x: x[1])

    # Статистика
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
#  4. Разбивка на чанки и создание файлов
# ═══════════════════════════════════════════════════════════════

def chunk_list(lst, size):
    """Разбить список на части по size элементов."""
    return [lst[i:i+size] for i in range(0, len(lst), size)]


def create_subscription_files(groups, output_dir):
    """
    Создаёт файлы {Регион}_part{N}_sub.txt в output_dir.
    Возвращает список: [(filename, region, part_num, key_count), ...]
    """
    os.makedirs(output_dir, exist_ok=True)
    file_meta = []

    for region in REGION_ORDER:
        keys = groups.get(region, [])
        if not keys:
            continue
        chunks = chunk_list([k for k, _ in keys], CHUNK_SIZE)
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
#  5. Git: клонирование + пуш в checked/
# ═══════════════════════════════════════════════════════════════

def push_to_repo(local_dir, file_meta):
    """Клонировать репозиторий, копировать файлы в checked/, пуш."""
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

    # Копируем файлы в checked/
    checked_path = os.path.join(clone_dir, CHECKED_DIR)
    os.makedirs(checked_path, exist_ok=True)

    for fname, _, _, _ in file_meta:
        src = os.path.join(local_dir, fname)
        dst = os.path.join(checked_path, fname)
        shutil.copy2(src, dst)

    # Git: add, commit, push
    subprocess.run(
        ["git", "add", "-A"],
        cwd=clone_dir, capture_output=True, timeout=30
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
        print(f"❌ Ошибка пуша: {push_result.stderr.strip()}")
        return False

    print(f"✅ Успешно запушено {len(file_meta)} файлов в {CHECKED_DIR}/")
    return True


# ═══════════════════════════════════════════════════════════════
#  6. Telegram: отправка
# ═══════════════════════════════════════════════════════════════

def send_photo(chat_id, photo_path, caption, bot_token):
    if DRY:
        print(f"[DRY] Отправка фото: {photo_path}")
        return True
    try:
        with open(photo_path, "rb") as ph:
            r = _sess.post(
                f"https://api.telegram.org/bot{bot_token}/sendPhoto",
                data={
                    "chat_id": chat_id,
                    "caption": caption,
                    "parse_mode": "HTML",
                },
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
    """
    Строит inline-клавиатуру.
    Каждая кнопка копирует в буфер прямую ссылку на файл на GitHub.
    Используем callback_data как хранилище ссылки (Telegram не поддерживает
    copy_text на кнопках, только через switch_inline_query — используем
    URL-кнопки с callback_data, пользователь получает ссылку через callback).
    """
    kb_rows = []
    current_row = []

    for fname, region, part_num, _ in file_meta:
        url = (
            f"https://raw.githubusercontent.com/"
            f"{REPO_OWNER}/{REPO_NAME}/{BRANCH}/{CHECKED_DIR}/{fname}"
        )
        label = f"📥 {region} (part {part_num})"
        # Обрезка до ~30 символов (лимит кнопки)
        if len(label) > 32:
            label = label[:29] + ".."

        current_row.append({
            "text": label,
            "url": url,
        })

        if len(current_row) == 2:
            kb_rows.append(current_row)
            current_row = []

    if current_row:
        kb_rows.append(current_row)

    return {"inline_keyboard": kb_rows}


def send_telegram(file_meta, total_keys):
    """Отправка обложки + сообщений с кнопками."""
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

    # Обложка
    time.sleep(1)
    if os.path.exists(COVER_PATH):
        ok = send_photo(CHANNEL_ID, COVER_PATH, caption, BOT_TOKEN)
        print(f"📸 Обложка отправлена: {ok}")
    else:
        ok = send_message(CHANNEL_ID, caption, BOT_TOKEN)
        print(f"📝 Сообщение-обложка отправлено: {ok}")

    # Кнопки (макс 100 кнопок на сообщение)
    keyboard = build_keyboard(file_meta)
    all_buttons = keyboard["inline_keyboard"]

    # Разбиваем по 100 кнопок (50 рядов по 2)
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
#  7. Main
# ═══════════════════════════════════════════════════════════════

def main():
    version = "PRIVATE POSTER v23"
    print(f"\n{'='*50}")
    print(f"{version} (DRY RUN = {'ON' if DRY else 'OFF'})")
    if DRY:
        print("    no posts, no pushes")
    print(f"{'='*50}\n")

    # 1. Загрузка и очистка
    keys = load_and_clean()
    if not keys:
        print("❌ Нет ключей для обработки")
        return 1

    # 2. TCP-проверка
    working = check_keys(keys)
    if not working:
        print("❌ Нет рабочих ключей")
        return 1

    # 3. Группировка по регионам
    groups = group_by_region(working)

    # 4. Создание файлов
    with tempfile.TemporaryDirectory(prefix="vpn_poster_") as tmpdir:
        file_meta = create_subscription_files(groups, tmpdir)

        if not file_meta:
            print("❌ Нет файлов для публикации")
            return 1

        # 5. Пуш на GitHub
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

        # 6. Telegram
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
