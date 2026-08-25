#!/usr/bin/env python3
"""
PRIVATE VPN POSTER — v34 (фиксы отчётности и гейт публикации)

Изменения относительно v33:
1. checked_count: в отчёт добавлено реальное количество проверенных
   ключей (после обрезки max_keys_to_check). Поле total_found
   переименовано по смыслу в raw_lines_found (сырых строк из всех
   источников до дедупликации/обрезки) — используется только для
   диагностики, НЕ для текста поста. В Telegram/AI должен идти
   checked_count, а не total_found/raw_lines_found.
2. should_publish_update(): пост в Telegram теперь публикуется только
   при существенном изменении (new_items>=3 ИЛИ removed_items>=10 ИЛИ
   |Δprotocol_passed|>=20% ИЛИ critical_drop=true). checked/ и push в
   GitHub всё равно обновляются каждый прогон — не публикуется только
   сам Telegram-пост. Причина логируется в diagnostics.jsonl
   (event=post_skipped, reason=minor_change).
3. xray_check_key(): fallback на второй контрольный URL теперь
   срабатывает не только при исключении, но и при плохом HTTP-статусе
   (например http_503) на основном XRAY_TEST_URL — один временный 503
   больше не отбраковывает рабочий ключ.
4. get_region_from_key(): регион определяется по IP (через опциональный
   GeoIP-словарь GEOIP_DB_PATH, MaxMind .mmdb + geoip2, если доступен),
   а не только по TLD домена. Если определить регион нельзя — ключ
   попадает в bucket "Unknown" (а не "Other"), и в отчёте это явно
   отличается от ошибки парсинга.

Изменения относительно v32 (сохранены из v33):
- Удалена ss:// → vless:// конвертация (критический баг).
- Поддержка схем: vless, vmess, trojan, ss, hysteria2, hy2.
- Уровни проверки L1 (parsing) / L2 (DNS) / L3 (TCP) / L4 (protocol).
- Запрет TCP-fallback: публикуются только ключи с protocol_passed=true.
- Xray: свободные локальные порты, уникальные tmp-диры, таймауты,
  лимит параллельных процессов, безопасные сообщения об ошибках.
- config/settings.yaml + переопределение переменными окружения.
- Отчёты: data/current_report.json, data/previous_report.json,
  data/diagnostics.jsonl.
- checked/manifest.json, атомарная замена, защита от пустого результата.
- replace_hosts по умолчанию выключен.
- В логах и отчётах нет полных URL конфигураций (sha256 / маскированный host).
"""
from __future__ import annotations

import base64
import hashlib
import html
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import parse_qs, unquote, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import yaml

from src.report_diff import compute_diff, load_report
from src.publish_update import publish_update

# ── Пути и константы ───────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(SCRIPT_DIR, "config", "settings.yaml")
REPORT_DIR = os.path.join(SCRIPT_DIR, "data")
CURRENT_REPORT = os.path.join(REPORT_DIR, "current_report.json")
PREVIOUS_REPORT = os.path.join(REPORT_DIR, "previous_report.json")
DIAGNOSTICS_LOG = os.path.join(REPORT_DIR, "diagnostics.jsonl")
CHECKED_DIR = os.path.join(SCRIPT_DIR, "checked")
COVER_PATH = os.path.join(SCRIPT_DIR, "cover_private.jpg")

SOURCE_URLS = [
    # Основные источники (vpn-vless-configs-russia, репозиторий владельца)
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/archive/subscriptions/all_base64.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/archive/subscriptions/all.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/archive/subscriptions/sni_filtered_base64.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/archive/my_sources/generated/vless.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/refs/heads/main/data/githubmirror/clean/vless.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/refs/heads/main/data/githubmirror/clean/hy2.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/refs/heads/main/data/githubmirror/clean/hysteria2.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/refs/heads/main/data/githubmirror/clean/ss.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/refs/heads/main/data/githubmirror/clean/trojan.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/refs/heads/main/data/githubmirror/new/cf_fresh.txt",
    # Дополнительные источники
    "https://raw.githubusercontent.com/VAL41K/bypass-rkn-blocks/refs/heads/main/configs/obhod_WL",
    "https://raw.githubusercontent.com/VAL41K/bypass-rkn-blocks/refs/heads/main/configs/obhod_BL",
]

REPO_OWNER = "kort0881"
REPO_NAME = "vpn-private-poster"
BRANCH = "main"

XRAY_BIN = os.environ.get("XRAY_BIN", os.path.join(SCRIPT_DIR, "bin", "xray"))
# Xray сам ищет geoip.dat/geosite.dat рядом с бинарником.
# Если нужен другой каталог assets — задать XRAY_ASSETS_DIR (→ XRAY_LOCATION_ASSET).
XRAY_ASSETS_DIR = os.environ.get("XRAY_ASSETS_DIR", "")
XRAY_TEST_URL = os.environ.get("XRAY_TEST_URL", "https://api.ipify.org?format=json")
XRAY_TEST_URL_FALLBACK = os.environ.get("XRAY_TEST_URL_FALLBACK", "http://1.1.1.1")
XRAY_TEST_URL_FALLBACK2 = os.environ.get(
    "XRAY_TEST_URL_FALLBACK2", "https://cp.cloudflare.com/generate_204"
)
MAX_XRAY_WORKERS = 3  # лимит параллельных Xray-процессов

# ── Гейт публикации поста (не путать с гейтом публикации файлов) ──
MIN_NEW_ITEMS_FOR_POST = _new_items_threshold = int(
    os.environ.get("MIN_NEW_ITEMS_FOR_POST", "3")
)
MIN_REMOVED_ITEMS_FOR_POST = int(os.environ.get("MIN_REMOVED_ITEMS_FOR_POST", "10"))
MIN_CHANGE_PERCENT_FOR_POST = float(os.environ.get("MIN_CHANGE_PERCENT_FOR_POST", "20"))

SUPPORTED_SCHEMES = (
    "vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://",
)
SCHEME_PATTERN = re.compile(
    r"^(vless|vmess|trojan|ss|hysteria2|hy2)://", re.IGNORECASE
)

KNOWN_SS_METHODS = {
    "aes-128-gcm", "aes-256-gcm",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "none",
}

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

# ISO country code → регион, используется при наличии GeoIP-базы.
COUNTRY_TO_REGION = {
    "DE": "Europe", "FR": "Europe", "NL": "Europe", "GB": "Europe",
    "IT": "Europe", "ES": "Europe", "SE": "Europe", "NO": "Europe",
    "FI": "Europe", "PL": "Europe", "CZ": "Europe", "AT": "Europe",
    "CH": "Europe", "BE": "Europe", "DK": "Europe", "IE": "Europe",
    "PT": "Europe", "GR": "Europe", "HU": "Europe", "RO": "Europe",
    "LV": "Europe", "LT": "Europe", "EE": "Europe", "BG": "Europe",
    "JP": "Asia", "SG": "Asia", "CN": "Asia", "HK": "Asia",
    "KR": "Asia", "IN": "Asia", "TW": "Asia", "MY": "Asia",
    "TH": "Asia", "VN": "Asia", "PH": "Asia", "ID": "Asia",
    "US": "USA",
    "RU": "Russia",
}

REGION_ORDER = ["Europe", "Asia", "USA", "Russia", "Unknown", "Other"]
CHUNK_SIZE = 100

# ── Опциональный GeoIP (MaxMind .mmdb) ──────────────────────
GEOIP_DB_PATH = os.environ.get("GEOIP_DB_PATH", "")
_geoip_reader = None
if GEOIP_DB_PATH and os.path.exists(GEOIP_DB_PATH):
    try:
        import geoip2.database  # type: ignore

        _geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
    except Exception as _exc:  # noqa: BLE001
        print(f"⚠️  Не удалось загрузить GeoIP-базу {GEOIP_DB_PATH}: {_exc}")
        _geoip_reader = None

_dns_cache: dict[str, str | None] = {}

_sess = requests.Session()
_r = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
_sess.mount("http://", HTTPAdapter(max_retries=_r))
_sess.mount("https://", HTTPAdapter(max_retries=_r))

# ── Настройки ──────────────────────────────────────────────
DEFAULTS = {
    "max_keys_to_check": 1000,
    "max_workers": 20,
    "tcp_timeout": 3,
    "xray_timeout": 8,
    "min_publish_count": 3,
    "publish_on_empty_result": False,
    "keep_previous_on_failure": True,
    "replace_hosts": False,
    "admin_review_required": True,
    "auto_publish": False,
    "max_source_age_days": 7,
}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def load_settings() -> dict:
    """Читает config/settings.yaml, переопределяет значениями env."""
    settings = dict(DEFAULTS)
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            if isinstance(data, dict):
                for k, v in data.items():
                    if k in settings:
                        settings[k] = v
        except (yaml.YAMLError, OSError) as exc:
            print(f"⚠️  Не удалось прочитать {CONFIG_PATH}: {exc}, используем defaults")

    env_map = {
        "max_keys_to_check": _env_int("MAX_KEYS_TO_CHECK", settings["max_keys_to_check"]),
        "max_workers": _env_int("MAX_WORKERS", settings["max_workers"]),
        "tcp_timeout": _env_int("TCP_TIMEOUT", settings["tcp_timeout"]),
        "xray_timeout": _env_int("XRAY_TIMEOUT", _env_int("XRAY_CHECK_TIMEOUT", settings["xray_timeout"])),
        "min_publish_count": _env_int("MIN_PUBLISH_COUNT", settings["min_publish_count"]),
        "publish_on_empty_result": _env_bool("PUBLISH_ON_EMPTY_RESULT", settings["publish_on_empty_result"]),
        "keep_previous_on_failure": _env_bool("KEEP_PREVIOUS_ON_FAILURE", settings["keep_previous_on_failure"]),
        "replace_hosts": _env_bool("REPLACE_HOSTS", settings["replace_hosts"]),
    }
    settings.update(env_map)
    return settings


SETTINGS = load_settings()

DRY = os.environ.get("TELEGRAM_DRY_RUN", "0") == "1"
BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
CHANNEL_ID = os.environ.get("TELEGRAM_PRIVATE_CHANNEL")
GH_TOKEN = os.environ.get("GH_TOKEN", os.environ.get("GITHUB_TOKEN", ""))
REPLACE_HOST = os.environ.get("REPLACE_HOST", "")

# ── Парсинг и очистка ──────────────────────────────────────
def is_supported_protocol(value: str) -> bool:
    """Проверяет, что строка начинается с поддерживаемой схемы."""
    return bool(SCHEME_PATTERN.match(value.strip()))


def clean_key(raw: str) -> str | None:
    """
    Очищает сырую строку из источника.

    - убирает пробелы по краям;
    - декодирует HTML-сущности (&amp; → & и т.п.);
    - обрезает комментарий (по первому пробелу/табуляции), если он есть;
    - НЕ меняет схему протокола;
    - возвращает None для явно некорректной строки.
    """
    if raw is None:
        return None
    k = str(raw)
    # Обрезаем по первому пробельному символу (комментарий/мусор после ключа)
    k = re.split(r"[ \t]+", k.strip(), maxsplit=1)[0]
    if not k:
        return None
    k = html.unescape(k)
    k = k.replace("&amp;", "&")  # на случай двойного кодирования
    if not k or len(k) < 12:
        return None
    return k


def parse_key(key: str) -> dict | None:
    """
    Разбирает ключ: схема, hostname, port, query.

    Возвращает dict {protocol, host, port, username, query} или None,
    если ключ некорректен (L1 parsing failed).
    """
    try:
        parsed = urlparse(key)
    except Exception:
        return None
    if not parsed.scheme or not is_supported_protocol(key):
        return None
    protocol = parsed.scheme.lower()
    host = parsed.hostname
    port = parsed.port
    query = parse_qs(parsed.query, keep_blank_values=True)

    # vmess://base64(JSON) — host/port внутри payload
    if protocol == "vmess":
        # Для vmess://b64 urlparse принимает b64 за netloc; берём его как payload
        vmess_payload = parsed.path.strip("/") or parsed.netloc
        vmess_data = _parse_vmess_payload(vmess_payload)
        if vmess_data:
            host = vmess_data.get("host")
            port = vmess_data.get("port")
            query = vmess_data.get("query", query)

    if not host:
        return None
    if not port:
        port = 443

    return {
        "protocol": protocol,
        "host": host,
        "port": port,
        "username": parsed.username or "",
        "query": query,
    }


def _parse_vmess_payload(path: str) -> dict | None:
    """Пытается распарсить vmess://base64(JSON). Возвращает None при неудаче."""
    payload = path.strip("/")
    try:
        # base64url-safe
        payload = payload.replace("-", "+").replace("_", "/")
        payload += "=" * (-len(payload) % 4)
        decoded = base64.b64decode(payload).decode("utf-8", errors="ignore")
        data = json.loads(decoded)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    host = data.get("add") or data.get("host")
    port_raw = data.get("port")
    try:
        port = int(port_raw) if port_raw else None
    except (TypeError, ValueError):
        port = None
    query = {
        "id": [str(data.get("id", ""))],
        "aid": [str(data.get("aid", 0))],
        "net": [str(data.get("net", "tcp"))],
        "type": [str(data.get("type", "none"))],
        "tls": [str(data.get("tls", "none"))],
        "sni": [str(data.get("sni", ""))],
        "host": [str(data.get("host", ""))],
        "path": [str(data.get("path", ""))],
        "fp": [str(data.get("fp", ""))],
        "scy": [str(data.get("scy", "auto"))],
    }
    return {"host": host, "port": port, "query": query}


def config_hash(key: str) -> str:
    """sha256 ключа — безопасный идентификатор для отчётов."""
    return hashlib.sha256(key.encode("utf-8", errors="ignore")).hexdigest()


def mask_key(key: str, show_chars: int = 6) -> str:
    """Маскированный вид ключа для логов: схема://host****."""
    p = parse_key(key)
    if not p:
        return f"{key[:8]}***"
    host = p["host"]
    if len(host) > show_chars:
        host = host[:show_chars] + "***"
    else:
        host = host + "***"
    return f"{p['protocol']}://{host}"


def deduplicate(keys: list[str]) -> tuple[list[str], int]:
    """Удаляет точные дубли. Возвращает (уникальные, число дублей)."""
    seen: dict[str, None] = {}
    dups = 0
    for k in keys:
        if k in seen:
            dups += 1
            continue
        seen[k] = None
    return list(seen.keys()), dups


def extract_host_port(key: str) -> tuple[str | None, int | None]:
    """host/port из ключа (для регионов и быстрых проверок)."""
    p = parse_key(key)
    if p:
        return p["host"], p["port"]
    m = re.search(r"@([^:]+):(\d+)", key)
    if m:
        return m.group(1), int(m.group(2))
    m = re.search(r"(?:server|add)=([^&:]+)(?::(\d+))?", key)
    if m:
        host = m.group(1)
        port = int(m.group(2)) if m.group(2) else 443
        return host, port
    return None, None


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _resolve_ip_cached(host: str) -> str | None:
    """DNS resolve с простым in-memory кэшем на один запуск."""
    if host in _dns_cache:
        return _dns_cache[host]
    try:
        ip = socket.gethostbyname(host)
    except OSError:
        ip = None
    _dns_cache[host] = ip
    return ip


def get_region_from_key(key: str) -> str:
    """
    Определяет регион серверa.

    Приоритет:
    1. GeoIP по IP-адресу (если задан GEOIP_DB_PATH и база загрузилась).
    2. TLD-эвристика — только если host НЕ является IP (для доменов
       вида example.de и т.п.; для IP и CDN-доменов TLD ничего не значит).
    3. "Unknown" — если ни один способ не сработал (не путать с "Other":
       "Other" зарезервирован для случаев, когда GeoIP явно вернул
       страну, не входящую в карту регионов).
    """
    host, _ = extract_host_port(key)
    if not host:
        return "Unknown"

    ip = host if _is_ip(host) else _resolve_ip_cached(host)

    if _geoip_reader and ip:
        try:
            resp = _geoip_reader.country(ip)
            code = resp.country.iso_code
            if code:
                return COUNTRY_TO_REGION.get(code, "Other")
        except Exception:
            pass

    if not _is_ip(host):
        parts = host.lower().split(".")
        if len(parts) >= 2 and parts[-1] in TLD_REGION:
            return TLD_REGION[parts[-1]]

    return "Unknown"


# ── L2 DNS / L3 TCP ────────────────────────────────────────
def dns_resolve(host: str) -> bool:
    try:
        socket.getaddrinfo(host, 80, socket.AF_INET, socket.SOCK_STREAM, 0, socket.AI_ADDRCONFIG)
        return True
    except (socket.gaierror, UnicodeError, OSError):
        # UnicodeEncodeError: битые/слишком длинные hostname (idna)
        return False


def tcp_check(host: str, port: int, timeout: float) -> float | None:
    """TCP-connect. Возвращает RTT в секундах или None."""
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


def get_free_port() -> int:
    """Возвращает свободный локальный TCP-порт."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ── L4 protocol: Xray ──────────────────────────────────────
def safe_error(exc: Exception) -> str:
    """Короткое безопасное описание ошибки без деталей ключа."""
    name = type(exc).__name__
    msg = str(exc)
    if isinstance(exc, (socket.timeout, TimeoutError)) or "timed out" in msg:
        return "timeout"
    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return "timeout"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "connection_error"
    if isinstance(exc, requests.exceptions.HTTPError):
        return f"http_{exc.response.status_code}" if exc.response is not None else "http_error"
    return name


def _stream_settings(protocol: str, query: dict) -> dict:
    """streamSettings для Xray по query-параметрам ключа."""
    def g(key: str, default=None):
        vals = query.get(key)
        if not vals:
            return default
        return vals[0]

    network = g("type") or g("net") or "tcp"
    security = g("security") or g("tls") or "none"
    if security in ("1", "true", "tls"):
        security = "tls"
    sni = g("sni") or g("peer") or g("host")
    fp = g("fp") or "chrome"

    stream = {
        "network": network,
        "security": security,
        "sockopt": {"tcpFastOpen": False},
    }

    if security in ("tls", "reality"):
        tls = {
            "allowInsecure": True,
            "serverName": sni,
            "fingerprint": fp,
        }
        if g("alpn"):
            tls["alpn"] = [a.strip() for a in g("alpn").split(",") if a.strip()]
        if security == "tls":
            stream["tlsSettings"] = tls
        else:
            reality = {
                "serverName": sni,
                "fingerprint": fp,
                "publicKey": g("pbk", ""),
                "shortId": g("sid", ""),
                "spiderX": g("spx", ""),
            }
            stream["realitySettings"] = reality

    if network == "ws":
        ws_settings = {"path": g("path", "/") or "/"}
        if g("host"):
            ws_settings["headers"] = {"Host": g("host")}
        stream["wsSettings"] = ws_settings
    elif network == "grpc":
        stream["grpcSettings"] = {"serviceName": g("serviceName", "")}
    elif network == "httpupgrade":
        hu = {"path": g("path", "/") or "/"}
        if g("host"):
            hu["host"] = g("host")
        stream["httpupgradeSettings"] = hu
    elif network in ("xhttp", "splithttp"):
        xh = {"path": g("path", "/") or "/", "host": g("host", "")}
        stream["xhttpSettings"] = xh

    return stream


def build_xray_config(key: str, proxy_port: int) -> dict | None:
    """
    Строит Xray-конфиг для ключа. Возвращает None, если протокол
    не поддерживается Xray-проверкой (например, hysteria2).
    """
    p = parse_key(key)
    if not p:
        return None
    protocol = p["protocol"]
    query = p["query"]

    def g(key: str, default=None):
        vals = query.get(key)
        if not vals:
            return default
        return vals[0]

    if protocol == "hysteria2" or protocol == "hy2":
        # Xray не умеет hysteria2-клиент — проверка недоступна
        return None

    if protocol == "vless":
        outbound = {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": p["host"],
                    "port": p["port"],
                    "users": [{
                        "id": p["username"] or g("id", ""),
                        "encryption": g("encryption", "none"),
                        "flow": g("flow", ""),
                        "level": 0,
                    }],
                }]
            },
            "streamSettings": _stream_settings(protocol, query),
        }
    elif protocol == "vmess":
        outbound = {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": p["host"],
                    "port": p["port"],
                    "users": [{
                        "id": p["username"] or g("id", ""),
                        "alterId": _env_int("VMESS_ALTER_ID", int(g("aid", 0) or 0)),
                        "security": g("scy", "auto"),
                        "level": 0,
                    }],
                }]
            },
            "streamSettings": _stream_settings(protocol, query),
        }
    elif protocol == "trojan":
        outbound = {
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": p["host"],
                    "port": p["port"],
                    "password": p["username"] or g("password", ""),
                    "level": 0,
                }]
            },
            "streamSettings": _stream_settings(protocol, query),
        }
    elif protocol == "ss":
        if detect_wrapped_vless(query):
            # ss-обёртка настоящего VLESS-ключa (reality/tls): проверяем как vless,
            # префикс не заменяем — в подписку идёт оригинальная строка.
            outbound = {
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": p["host"],
                        "port": p["port"],
                        "users": [{
                            "id": unquote(p["username"] or ""),
                            "encryption": g("encryption", "none"),
                            "flow": g("flow", ""),
                            "level": 0,
                        }],
                    }]
                },
                "streamSettings": _stream_settings("vless", query),
            }
        else:
            method, password = _parse_ss(key, p)
            if method in KNOWN_SS_METHODS and password:
                outbound = {
                    "protocol": "shadowsocks",
                    "settings": {
                        "servers": [{
                            "address": p["host"],
                            "port": p["port"],
                            "method": method,
                            "password": password,
                            "level": 0,
                        }]
                    },
                    "streamSettings": {"network": "tcp", "security": "none"},
                }
            else:
                return None
    else:
        return None

    return {
        "log": {"loglevel": "error"},
        "inbounds": [{
            "protocol": "http",
            "port": proxy_port,
            "listen": "127.0.0.1",
            "settings": {"auth": "noauth"},
        }],
        "outbounds": [outbound],
    }


def _parse_ss(key: str, p: dict) -> tuple[str | None, str | None]:
    """Возвращает (method, password) для настоящего ss:// ключа."""
    try:
        parsed = urlparse(key)
        userinfo = parsed.username or ""
        if ":" in userinfo and not parsed.password:
            method, password = userinfo.split(":", 1)
            return method, password
        if parsed.password:
            return parsed.username or "", parsed.password
    except Exception:
        pass
    # Формат ss://base64(method:password)@host:port
    m = re.match(r"ss://([A-Za-z0-9+/=_-]+)@", key)
    if m:
        b64 = m.group(1).replace("-", "+").replace("_", "/")
        b64 += "=" * (-len(b64) % 4)
        try:
            decoded = base64.b64decode(b64).decode("utf-8", errors="ignore")
            if ":" in decoded:
                method, password = decoded.split(":", 1)
                return method, password
        except Exception:
            return None, None
    # ss://base64(method:password@host:port)
    m = re.match(r"ss://([A-Za-z0-9+/=_-]+)$", key)
    if m:
        b64 = m.group(1).replace("-", "+").replace("_", "/")
        b64 += "=" * (-len(b64) % 4)
        try:
            decoded = base64.b64decode(b64).decode("utf-8", errors="ignore")
            if ":" in decoded and "@" in decoded:
                method, rest = decoded.split(":", 1)
                return method, rest.split("@")[0]
        except Exception:
            return None, None
    return None, None


def detect_wrapped_vless(query: dict) -> bool:
    """
    Определяет, является ли ключ с префиксом ss:// на самом деле
    VLESS-конфигурацией (ss-обёртка: reality/tls + pbk/sid/flow).

    Используется ТОЛЬКО для выбора логики ПРОВЕРКИ. Префикс в ключе
    никогда не заменяется — в подписки попадает оригинальная строка.
    """
    if "pbk" in query or "sid" in query:
        return True
    sec = (query.get("security") or [""])[0]
    if sec in ("reality", "tls"):
        return True
    if "flow" in query and (query.get("encryption") or [""])[0] == "none":
        return True
    return False


def _probe(url: str, proxies: dict, timeout: float) -> tuple[int | None, str | None]:
    """Один HTTP-запрос через прокси. Возвращает (status_code|None, error_code|None)."""
    try:
        r = requests.get(url, proxies=proxies, timeout=timeout)
        return r.status_code, None
    except requests.exceptions.RequestException as exc:
        return None, safe_error(exc)


def xray_check_key(
    key: str,
    proxy_port: int,
    timeout: float,
    xray_bin: str = XRAY_BIN,
) -> tuple[bool, float | None, str | None]:
    """
    Проверяет ключ через Xray (L4 protocol).

    Возвращает (успех, rtt_сек, error_code|None).
    error_code — безопасная короткая причина ('timeout', 'xray_crash', ...).

    v34: если основной контрольный URL вернул успешный ответ (2xx-3xx) —
    засчитываем сразу. Если он вернул ЛЮБУЮ ошибку (плохой HTTP-статус
    ИЛИ исключение), пробуем по очереди резервные URL, прежде чем
    признать ключ нерабочим. Один временный http_503 на одном сервисе
    больше не отбраковывает рабочую конфигурацию.
    """
    if not os.path.exists(xray_bin):
        return False, None, "xray_missing"

    config = build_xray_config(key, proxy_port)
    if config is None:
        return False, None, "protocol_not_supported"

    tmpdir = tempfile.mkdtemp(prefix="xray_check_")
    config_path = os.path.join(tmpdir, "config.json")
    log_path = os.path.join(tmpdir, "xray.log")
    proc = None

    try:
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f)

        cmd = [xray_bin, "-c", config_path]
        # Флага -assets/-assetsDir в Xray 25.x нет; путь к assets задаётся
        # env XRAY_LOCATION_ASSET, а по умолчанию Xray ищет их рядом с бинарником.
        popen_env = None
        if XRAY_ASSETS_DIR:
            popen_env = {**os.environ, "XRAY_LOCATION_ASSET": XRAY_ASSETS_DIR}

        logf = open(log_path, "w", encoding="utf-8")
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=logf,
                stderr=subprocess.STDOUT,
                env=popen_env,
                preexec_fn=os.setsid if os.name == "posix" else None,
            )
        finally:
            logf.close()

        time.sleep(0.8)
        if proc.poll() is not None:
            # Процесс умер сразу — читаем хвост лога (безопасно, без URL)
            reason = "xray_crash"
            try:
                with open(log_path, "r", encoding="utf-8", errors="ignore") as lf:
                    lines = [ln.strip() for ln in lf if ln.strip()]
                if lines:
                    tail = lines[-1][:80]
                    reason = f"xray_crash:{tail}"
            except OSError:
                pass
            return False, None, reason

        proxies = {"http": f"http://127.0.0.1:{proxy_port}", "https": f"http://127.0.0.1:{proxy_port}"}
        probe_urls = [XRAY_TEST_URL, XRAY_TEST_URL_FALLBACK, XRAY_TEST_URL_FALLBACK2]

        last_err = "protocol_failed"
        for idx, url in enumerate(probe_urls):
            start = time.time()
            status, err = _probe(url, proxies, timeout)
            elapsed = time.time() - start
            if status is not None and 200 <= status < 400:
                return True, round(elapsed, 3), None
            last_err = err or (f"http_{status}" if status is not None else "unknown_error")
            # переходим к следующему probe URL, если этот не сработал

        return False, None, last_err

    except Exception as exc:
        return False, None, safe_error(exc)

    finally:
        if proc:
            try:
                if os.name == "posix":
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                else:
                    proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        shutil.rmtree(tmpdir, ignore_errors=True)


# ── Полный цикл проверки ключа ─────────────────────────────
def check_one(
    key: str,
    settings: dict,
    with_protocol: bool = True,
) -> dict | None:
    """
    Проверяет ключ по уровням L1-L4.

    Возвращает dict-результат или None, если ключ не прошёл L1.
    Никогда не содержит полный ключ.
    """
    p = parse_key(key)
    if not p:
        return {
            "config_hash": config_hash(key),
            "protocol": "unknown",
            "region": "Unknown",
            "check_level": "parse",
            "status": "dead",
            "latency": None,
            "error_code": "parse_failed",
            "levels_passed": [],
            "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }

    region = get_region_from_key(key)
    # Фактический протокол: ss:// может быть обёрткой настоящего VLESS
    protocol = p["protocol"]
    if protocol == "ss":
        if detect_wrapped_vless(p["query"]):
            protocol = "vless"
        else:
            method, password = _parse_ss(key, p)
            if not (method in KNOWN_SS_METHODS and password):
                protocol = "ss_invalid"
    base = {
        "config_hash": config_hash(key),
        "protocol": protocol,
        "region": region,
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }

    # L2 DNS
    if not dns_resolve(p["host"]):
        return {**base, "check_level": "dns", "status": "dead", "latency": None,
                "error_code": "dns_failed", "levels_passed": ["parse"]}

    # L3 TCP
    rtt = tcp_check(p["host"], p["port"], settings["tcp_timeout"])
    if rtt is None:
        return {**base, "check_level": "tcp", "status": "dead", "latency": None,
                "error_code": "tcp_failed", "levels_passed": ["parse", "dns"]}

    # Hysteria2: UDP/QUIC — Xray-проверка недоступна, остаётся tcp_only
    if p["protocol"] in ("hysteria2", "hy2"):
        return {**base, "check_level": "tcp_only", "status": "working", "latency": rtt,
                "error_code": "hysteria2_udp_not_supported",
                "levels_passed": ["parse", "dns", "tcp"]}

    result = {**base, "check_level": "tcp", "status": "working", "latency": rtt,
              "error_code": None, "levels_passed": ["parse", "dns", "tcp"]}

    # L4 protocol
    if with_protocol:
        port = get_free_port()
        ok, x_rtt, err = xray_check_key(key, port, settings["xray_timeout"])
        if ok:
            result.update({
                "check_level": "protocol",
                "status": "working",
                "latency": x_rtt if x_rtt else rtt,
                "error_code": None,
                "levels_passed": ["parse", "dns", "tcp", "protocol"],
            })
        else:
            result.update({
                "check_level": "protocol",
                "status": "dead",
                "error_code": err or "protocol_failed",
            })

    return result


def check_all(keys: list[str], settings: dict) -> list[dict]:
    """Параллельная проверка L1-L3, затем Xray (L4) с лимитом процессов."""
    total = len(keys)
    results: list[dict] = []

    print(f"\n🔍 Проверка {total} ключей ({settings['max_workers']} потоков, TCP-таймаут {settings['tcp_timeout']}с)...")

    # Шаг 1: L1-L3 параллельно
    with ThreadPoolExecutor(max_workers=settings["max_workers"]) as executor:
        futures = {executor.submit(check_one, key, settings, with_protocol=False): idx for idx, key in enumerate(keys, 1)}
        for future in as_completed(futures):
            idx = futures[future]
            res = future.result()
            results.append(res)
            if res is None:
                print(f"  [{idx}/{total}] ❌ parse")
                continue
            if res["status"] == "working":
                print(f"  [{idx}/{total}] ✅ L3 tcp {round(res['latency']*1000,1)} мс ({res['region']}, {res['protocol']})")
            else:
                print(f"  [{idx}/{total}] ❌ {res['error_code']} ({res['protocol']})")

    # Шаг 2: L4 protocol (Xray) с ограничением параллельных процессов
    tcp_ok = [r for r in results if r["status"] == "working" and r["check_level"] == "tcp"]
    hy2 = [r for r in results if r.get("error_code") == "hysteria2_udp_not_supported"]
    if not os.path.exists(XRAY_BIN):
        print("⚠️  Xray не найден — протокольная проверка (L4) недоступна")
    elif tcp_ok:
        key_by_hash = {config_hash(k): k for k in keys}
        print(f"\n🧪 Протокольная проверка (L4) {len(tcp_ok)} ключей через Xray...")
        done = 0
        with ThreadPoolExecutor(max_workers=MAX_XRAY_WORKERS) as executor:
            futures = {
                executor.submit(xray_check_key, key_by_hash[r["config_hash"]], get_free_port(), settings["xray_timeout"]): r
                for r in tcp_ok
            }
            for future in as_completed(futures):
                res = futures[future]
                ok, x_rtt, err = future.result()
                done += 1
                if ok:
                    res.update({
                        "check_level": "protocol",
                        "latency": x_rtt if x_rtt else res["latency"],
                        "error_code": None,
                        # Важно: L4-успех обязан добавить "protocol" в levels_passed,
                        # иначе build_report считает protocol_passed=0 и items пустыми
                        # (баг v32, из-за которого в посте было «прошли: 0»).
                        "levels_passed": ["parse", "dns", "tcp", "protocol"],
                    })
                    print(f"  [{done}/{len(tcp_ok)}] ✅ L4 protocol {round((x_rtt or 0)*1000,1)} мс ({res['region']})")
                else:
                    res.update({"check_level": "protocol", "status": "dead", "error_code": err or "protocol_failed"})
                    print(f"  [{done}/{len(tcp_ok)}] ❌ L4 {res['error_code']} ({res['region']})")

    verified = [r for r in results if r["status"] == "working" and r["check_level"] == "protocol"]
    tcp_only = [r for r in results if r["status"] == "working" and r["check_level"] in ("tcp", "tcp_only")]
    print(f"\n✅ protocol_passed: {len(verified)}, tcp_only: {len(tcp_only)} (не публикуются как verified), hy2: {len(hy2)}")
    return results


# ── Отчёты ─────────────────────────────────────────────────
def rotate_reports() -> None:
    """Текущий отчёт → previous. Не затирает при отсутствии current."""
    os.makedirs(REPORT_DIR, exist_ok=True)
    if os.path.exists(CURRENT_REPORT):
        try:
            shutil.copy2(CURRENT_REPORT, PREVIOUS_REPORT)
        except OSError as exc:
            print(f"⚠️  Не удалось сохранить previous_report: {exc}")


def append_diagnostics(entry: dict) -> None:
    """Дописывает безопасную запись в diagnostics.jsonl."""
    os.makedirs(REPORT_DIR, exist_ok=True)
    entry.setdefault("ts", datetime.now(timezone.utc).isoformat(timespec="seconds"))
    try:
        with open(DIAGNOSTICS_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError as exc:
        print(f"⚠️  Не удалось записать diagnostics: {exc}")


def write_report(report: dict) -> None:
    """Пишет отчёт во временный файл, затем атомарно заменяет current."""
    os.makedirs(REPORT_DIR, exist_ok=True)
    tmp_path = CURRENT_REPORT + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    os.replace(tmp_path, CURRENT_REPORT)


def build_report(
    results: list[dict],
    raw_lines_found: int,
    checked_count: int,
    parsed: int,
    duration: float,
    publish_allowed: bool,
    published_count: int,
    settings: dict,
) -> dict:
    """
    Собирает current_report.json по формату ТЗ.

    v34: добавлено поле checked_count — реальное число ключей, которые
    прошли проверку в этом запуске (после обрезки max_keys_to_check).
    Поле total_found переименовано по смыслу в raw_lines_found: это
    сырое количество уникальных строк из ВСЕХ источников ДО обрезки
    (может быть кратно больше checked_count) — используется только
    для диагностики и НЕ должно попадать в текст Telegram-поста.
    """
    working = [r for r in results if r["status"] == "working"]
    protocol_passed = [r for r in results if "protocol" in r.get("levels_passed", []) and r["status"] == "working"]
    tcp_passed = [r for r in results if "tcp" in r.get("levels_passed", [])]
    dns_passed = [r for r in results if "dns" in r.get("levels_passed", [])]
    parsed_list = [r for r in results if r.get("levels_passed", []) or r["status"] == "working"]

    by_protocol: dict[str, int] = {}
    by_region: dict[str, int] = {}
    by_check_level: dict[str, int] = {}
    for r in working:
        by_protocol[r["protocol"]] = by_protocol.get(r["protocol"], 0) + 1
        by_region[r["region"]] = by_region.get(r["region"], 0) + 1
        by_check_level[r["check_level"]] = by_check_level.get(r["check_level"], 0) + 1

    failures = {"parse": 0, "dns": 0, "tcp": 0, "protocol": 0, "timeout": 0, "unsupported": 0}
    for r in results:
        code = r.get("error_code") or ""
        if r["check_level"] == "parse":
            failures["parse"] += 1
        elif r["check_level"] == "dns":
            failures["dns"] += 1
        elif r["check_level"] == "tcp" and r["status"] == "dead":
            failures["tcp"] += 1
        elif r["check_level"] == "protocol" and r["status"] == "dead":
            failures["protocol"] += 1
        if code == "timeout":
            failures["timeout"] += 1
        if code in ("unsupported_protocol", "hysteria2_udp_not_supported"):
            failures["unsupported"] += 1

    prev = load_report(PREVIOUS_REPORT)
    diff = compute_diff(prev, {"protocol_passed": len(protocol_passed), "items": protocol_passed})

    report = {
        "schema_version": 2,
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "duration_seconds": round(duration, 2),
        # v34: используем в постах ТОЛЬКО checked_count.
        "checked_count": checked_count,
        "raw_lines_found": raw_lines_found,
        # total_found оставлен для обратной совместимости со старыми
        # промтами/шаблонами, но НЕ должен использоваться в текстах постов.
        "total_found": raw_lines_found,
        "parsed": len(parsed_list),
        "dns_passed": len(dns_passed),
        "tcp_passed": len(tcp_passed),
        "protocol_passed": len(protocol_passed),
        "published_count": published_count,
        "by_protocol": by_protocol,
        "by_region": by_region,
        "by_check_level": by_check_level,
        "failures": failures,
        "new_items": diff["new_count"],
        "removed_items": diff["removed_count"],
        "stable_items": diff["stable_count"],
        "critical_drop": diff["critical_drop"],
        "publish_allowed": publish_allowed,
        "items": protocol_passed,
    }
    return report


def should_publish_update(report: dict) -> dict:
    """
    v34: гейт для ПОСТА в Telegram (не для обновления checked/ и push —
    те выполняются всегда при успешной проверке).

    Пост публикуется только при существенном изменении:
    - new_items >= MIN_NEW_ITEMS_FOR_POST, ИЛИ
    - removed_items >= MIN_REMOVED_ITEMS_FOR_POST, ИЛИ
    - |Δ protocol_passed| относительно предыдущего отчёта >=
      MIN_CHANGE_PERCENT_FOR_POST %, ИЛИ
    - critical_drop=true.

    Возвращает {"publish": bool, "reason": str, "change_percent": float}.
    """
    new_items = report.get("new_items", 0) or 0
    removed_items = report.get("removed_items", 0) or 0
    protocol_passed = report.get("protocol_passed", 0) or 0
    critical_drop = bool(report.get("critical_drop", False))

    prev = load_report(PREVIOUS_REPORT) or {}
    prev_passed = prev.get("protocol_passed", protocol_passed) or 0

    if prev_passed <= 0:
        change_percent = 100.0 if protocol_passed > 0 else 0.0
    else:
        change_percent = abs(protocol_passed - prev_passed) / prev_passed * 100

    significant = (
        new_items >= MIN_NEW_ITEMS_FOR_POST
        or removed_items >= MIN_REMOVED_ITEMS_FOR_POST
        or change_percent >= MIN_CHANGE_PERCENT_FOR_POST
        or critical_drop
    )

    if not significant:
        return {
            "publish": False,
            "reason": "minor_change",
            "change_percent": round(change_percent, 1),
        }
    return {
        "publish": True,
        "reason": "significant_change",
        "change_percent": round(change_percent, 1),
    }


# ── Публикация файлов ──────────────────────────────────────
def replace_hosts_in_key(key: str, new_host: str) -> str:
    """Заменяет hostname в ключе (используется ТОЛЬКО при replace_hosts=true)."""
    key = re.sub(r"@([^:@\s]+)", f"@{new_host}", key)
    key = re.sub(r"(server|add)=([^&\s]+)", rf"\1={new_host}", key)
    return key


def prepare_keys_for_publish(verified_keys: list[tuple[str, dict]], settings: dict) -> list[tuple[str, dict]]:
    """
    Готовит ключи к публикации. Если replace_hosts=true — заменяет hostname
    и перепроверяет ключ (публикуются только успешно проверенные замены).
    """
    if not settings["replace_hosts"]:
        return verified_keys
    if not REPLACE_HOST:
        print("⚠️  replace_hosts=true, но REPLACE_HOST не задан — замены не будет")
        return verified_keys
    out = []
    for key, res in verified_keys:
        new_key = replace_hosts_in_key(key, REPLACE_HOST)
        if new_key == key:
            out.append((key, res))
            continue
        recheck = check_one(new_key, settings, with_protocol=True)
        if recheck and recheck["status"] == "working" and recheck["check_level"] == "protocol":
            out.append((new_key, recheck))
            print(f"  ✅ заменён и перепроверен: {mask_key(new_key)}")
        else:
            append_diagnostics({
                "event": "replace_host_recheck_failed",
                "config_hash": config_hash(key),
                "error_code": (recheck or {}).get("error_code", "unknown"),
            })
            print(f"  ⚠️  заменённый ключ не прошёл проверку — пропущен: {mask_key(new_key)}")
    return out


def create_subscription_files(groups: "OrderedDict[str, list[tuple[str, dict]]]", output_dir: str) -> list[dict]:
    """Пишет файлы подписок. Возвращает file_meta (для manifest)."""
    os.makedirs(output_dir, exist_ok=True)
    file_meta = []
    for region in REGION_ORDER:
        items = groups.get(region, [])
        if not items:
            continue
        keys = [k for k, _ in items]
        chunks = [keys[i:i + CHUNK_SIZE] for i in range(0, len(keys), CHUNK_SIZE)]
        for part_num, chunk in enumerate(chunks, 1):
            fname = f"{region}_part{part_num}_sub.txt"
            fpath = os.path.join(output_dir, fname)
            with open(fpath, "w", encoding="utf-8") as f:
                f.write("\n".join(chunk) + "\n")
            file_meta.append({
                "name": fname,
                "region": region,
                "count": len(chunk),
                "check_level": "protocol",
                "last_verified": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            })
    print(f"\n✅ Создано файлов подписок: {len(file_meta)}")
    for m in file_meta:
        print(f"   {m['name']} ({m['count']} ключей) — {m['region']}")
    return file_meta


def build_manifest(file_meta: list[dict]) -> dict:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "files": file_meta,
    }


def atomic_replace_checked(source_dir: str, file_meta: list[dict], manifest: dict, min_publish_count: int) -> bool:
    """
    Атомарно обновляет checked/: файлы уже записаны в source_dir (stage),
    проверяются на непустоту и минимальное количество, затем заменяют
    старые. Устаревшие part-файлы удаляются.
    """
    if not file_meta:
        return False
    os.makedirs(CHECKED_DIR, exist_ok=True)

    # Проверки перед заменой
    total_count = sum(m["count"] for m in file_meta)
    if total_count < min_publish_count:
        print(f"❌ Мало ключей для публикации: {total_count} < min_publish_count={min_publish_count} — checked/ не обновляется")
        return False
    for m in file_meta:
        src = os.path.join(source_dir, m["name"])
        if not os.path.exists(src) or os.path.getsize(src) == 0:
            print(f"❌ Файл {m['name']} пуст или отсутствует — checked/ не обновляется")
            return False

    try:
        # Удаляем старые part-файлы, которых нет в новом наборе
        new_names = {m["name"] for m in file_meta}
        for old in os.listdir(CHECKED_DIR):
            if old.endswith("_sub.txt") and old not in new_names:
                try:
                    os.remove(os.path.join(CHECKED_DIR, old))
                except OSError:
                    pass
        # Заменяем файлы
        for m in file_meta:
            os.replace(os.path.join(source_dir, m["name"]), os.path.join(CHECKED_DIR, m["name"]))
        manifest_path = os.path.join(source_dir, "manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, ensure_ascii=False, indent=2)
        os.replace(manifest_path, os.path.join(CHECKED_DIR, "manifest.json"))
        print(f"✅ checked/ обновлён атомарно: {len(file_meta)} файлов + manifest.json")
        return True
    except OSError as exc:
        print(f"❌ Ошибка обновления checked/: {exc}")
        return False


def group_and_sort(verified: list[tuple[str, dict]]) -> "OrderedDict[str, list[tuple[str, dict]]]":
    groups: "OrderedDict[str, list[tuple[str, dict]]]" = OrderedDict()
    for r in REGION_ORDER:
        groups[r] = []
    for key, res in verified:
        region = res.get("region", "Unknown")
        if region not in groups:
            region = "Unknown"
        groups[region].append((key, res))
    for region in groups:
        groups[region].sort(key=lambda x: x[1].get("latency") or 999)
    return groups


# ── Push в GitHub ───────────────────────────────────────────
def _redact(text: str) -> str:
    if GH_TOKEN and GH_TOKEN in text:
        text = text.replace(GH_TOKEN, "***")
    return text


def push_to_repo() -> bool:
    """Клонирует репозиторий и пушит checked/ целиком (файлы + manifest)."""
    repo_url = f"https://kort0881:{GH_TOKEN}@github.com/{REPO_OWNER}/{REPO_NAME}.git"
    print(f"\n📦 Клонирование {REPO_OWNER}/{REPO_NAME}...")
    clone_dir = os.path.join(tempfile.gettempdir(), "vpn_poster_repo_clone")
    if os.path.exists(clone_dir):
        shutil.rmtree(clone_dir)

    result = subprocess.run(
        ["git", "clone", repo_url, clone_dir, "--depth=1"],
        capture_output=True, text=True, timeout=60
    )
    if result.returncode != 0:
        print(f"❌ Ошибка клонирования: {_redact(result.stderr.strip())}")
        return False

    checked_path = os.path.join(clone_dir, CHECKED_DIR.split(os.sep)[-1])
    os.makedirs(checked_path, exist_ok=True)

    for fname in os.listdir(CHECKED_DIR):
        if fname.endswith((".txt", ".json")):
            shutil.copy2(os.path.join(CHECKED_DIR, fname), os.path.join(checked_path, fname))

    subprocess.run(["git", "add", "-A"], cwd=clone_dir, capture_output=True, timeout=30)
    subprocess.run(["git", "config", "user.name", "GitHub Actions Bot"], cwd=clone_dir, capture_output=True, timeout=10)
    subprocess.run(["git", "config", "user.email", "actions@github.com"], cwd=clone_dir, capture_output=True, timeout=10)

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    commit_result = subprocess.run(
        ["git", "commit", "-m", f"Auto update subscription files — {ts}"],
        cwd=clone_dir, capture_output=True, text=True, timeout=30
    )
    if commit_result.returncode != 0 and "nothing to commit" not in commit_result.stderr:
        print(f"❌ Ошибка коммита: {_redact(commit_result.stderr.strip())}")
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
                print(f"❌ Ошибка rebase: {_redact(pull_result.stderr.strip())}")
                return False
            push_result = subprocess.run(
                ["git", "push", "origin", BRANCH],
                cwd=clone_dir, capture_output=True, text=True, timeout=60
            )
            if push_result.returncode != 0:
                print(f"❌ Ошибка пуша: {_redact(push_result.stderr.strip())}")
                return False
        else:
            print(f"❌ Ошибка пуша: {_redact(push_result.stderr.strip())}")
            return False
    print(f"✅ Успешно запушено {CHECKED_DIR}/ в репозиторий")
    return True


# ── Telegram ────────────────────────────────────────────────
def send_photo(chat_id: str, photo_path: str, caption: str, bot_token: str) -> bool:
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


def send_message(chat_id: str, text: str, bot_token: str, reply_markup=None) -> bool:
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


def build_keyboard(file_meta: list[dict]) -> dict:
    kb_rows = []
    current_row = []
    for m in file_meta:
        url = (
            f"https://raw.githubusercontent.com/"
            f"{REPO_OWNER}/{REPO_NAME}/{BRANCH}/checked/{m['name']}"
        )
        label = f"📥 {m['region']} (part {m['name'].split('_part')[1][0]})"
        if len(label) > 32:
            label = label[:29] + ".."
        current_row.append({"text": label, "url": url})
        if len(current_row) == 2:
            kb_rows.append(current_row)
            current_row = []
    if current_row:
        kb_rows.append(current_row)
    return {"inline_keyboard": kb_rows}


def send_telegram(report: dict, file_meta: list[dict]) -> bool:
    """
    ТЗ3: единая публикация технического поста обновления.

    v34: перед вызовом publish_update() в main() уже применён гейт
    should_publish_update(); эта функция вызывается только если
    решение "publish" — она сама по себе гейт не повторяет.
    """
    if not BOT_TOKEN or not CHANNEL_ID:
        print("⚠️  TELEGRAM_BOT_TOKEN или TELEGRAM_PRIVATE_CHANNEL не заданы")
        return False
    stats = publish_update(report, file_meta, dry_run=DRY)
    if DRY:
        return True  # dry-run: пост сформирован и показан в preview
    return bool(stats["published"] or stats["skipped"])


# ── Загрузка ключей ─────────────────────────────────────────
def fetch_raw_keys(url: str) -> list[str]:
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


def load_and_clean(settings: dict) -> tuple[list[str], int, int]:
    """
    Загрузка + очистка + дедупликация.

    Возвращает (уникальные ключи для проверки, raw_lines_found, число дублей).

    raw_lines_found — количество уникальных валидных строк из ВСЕХ
    источников ДО обрезки по max_keys_to_check. Это диагностическое
    число (может быть намного больше реально проверенных ключей) —
    НЕ показывать его в Telegram-постах как "проверили X".
    """
    raw_seen: OrderedDict = OrderedDict()
    for url in SOURCE_URLS:
        raw = fetch_raw_keys(url)
        if not raw:
            continue
        for line in raw:
            k = clean_key(line)
            if not k or not is_supported_protocol(k):
                continue
            raw_seen[k] = True
    raw_lines_found = len(raw_seen)

    max_keys = settings["max_keys_to_check"]
    if max_keys > 0 and len(raw_seen) > max_keys:
        print(f"⚠️  Слишком много ключей ({len(raw_seen)}), проверяем только {max_keys}")
        raw_seen = OrderedDict(list(raw_seen.items())[:max_keys])

    keys = list(raw_seen.keys())
    unique, dups = deduplicate(keys)
    print(f"✅ После очистки и дедупликации: {len(unique)} уникальных (дублей: {dups})")
    return unique, raw_lines_found, dups


# ── main ────────────────────────────────────────────────────
def main() -> int:
    settings = load_settings()
    version = "PRIVATE POSTER v34 (checked_count, publish-gate, multi-probe L4, GeoIP-регион)"
    print(f"\n{'='*50}")
    print(f"{version} (DRY RUN = {'ON' if DRY else 'OFF'})")
    print(f"Xray binary: {XRAY_BIN}")
    print(f"Макс. ключей: {settings['max_keys_to_check']}, min_publish: {settings['min_publish_count']}, "
          f"replace_hosts: {settings['replace_hosts']}")
    print(f"{'='*50}\n")

    start = time.time()
    rotate_reports()

    keys, raw_lines_found, dups = load_and_clean(settings)
    checked_count = len(keys)
    if not keys:
        print("❌ Нет ключей для обработки")
        append_diagnostics({"event": "no_keys", "raw_lines_found": raw_lines_found})
        return 1

    results = check_all(keys, settings)
    parsed = sum(1 for r in results if r["check_level"] != "parse")
    verified = [r for r in results if r["status"] == "working" and r["check_level"] == "protocol"]

    publish_allowed = len(verified) >= settings["min_publish_count"]
    if not publish_allowed:
        reason = (f"protocol_passed={len(verified)} < min_publish_count={settings['min_publish_count']}"
                  if verified else "нет ни одного ключа, прошедшего протокольную проверку")
        print(f"\n🚫 Публикация запрещена: {reason}")
        if not settings["publish_on_empty_result"]:
            append_diagnostics({
                "event": "publish_blocked",
                "reason": reason,
                "protocol_passed": len(verified),
                "min_publish_count": settings["min_publish_count"],
            })
            # Не затираем checked/ — предыдущий набор сохраняется
            if settings["keep_previous_on_failure"]:
                print("🛡️ checked/ не тронут (keep_previous_on_failure=true)")
            duration = time.time() - start
            report = build_report(results, raw_lines_found, checked_count, parsed, duration, False, 0, settings)
            write_report(report)
            return 1

    # Собираем ключи для публикации
    key_by_hash = {config_hash(k): k for k in keys}
    verified_keys = [(key_by_hash[r["config_hash"]], r) for r in verified]
    verified_keys = prepare_keys_for_publish(verified_keys, settings)

    if not verified_keys:
        print("❌ После подготовки к публикации ключей не осталось")
        duration = time.time() - start
        report = build_report(results, raw_lines_found, checked_count, parsed, duration, False, 0, settings)
        write_report(report)
        return 1

    groups = group_and_sort(verified_keys)
    total_to_publish = sum(len(v) for v in groups.values())

    stage_dir = tempfile.mkdtemp(prefix="checked_stage_", dir=SCRIPT_DIR)
    try:
        file_meta = create_subscription_files(groups, stage_dir)
        manifest = build_manifest(file_meta)

        if not file_meta:
            print("❌ Нет файлов для публикации")
            return 1

        # Атомарная замена checked/
        if not atomic_replace_checked(stage_dir, file_meta, manifest, settings["min_publish_count"]):
            print("❌ Не удалось обновить checked/ — публикация отменена")
            return 1
    finally:
        shutil.rmtree(stage_dir, ignore_errors=True)

    if DRY:
        print(f"\n[DRY] Пуш в репозиторий пропущен.")
    else:
        if not GH_TOKEN:
            print("⚠️  GH_TOKEN не задан — пуш невозможен")
            return 1
        push_ok = push_to_repo()
        if not push_ok:
            print("❌ Ошибка пуша в репозиторий")
            return 1

    # Отчёт пишем до публикации: publish_update использует данные отчёта
    # (ТЗ3: AI получает только current_report.json и безопасные метаданные).
    duration = time.time() - start
    report = build_report(results, raw_lines_found, checked_count, parsed, duration, True, total_to_publish, settings)
    write_report(report)

    # v34: гейт публикации ПОСТА (checked/ и push уже обновлены выше в любом случае)
    decision = should_publish_update(report)
    print(
        f"\nℹ️  Решение по посту: publish={decision['publish']} "
        f"reason={decision['reason']} change={decision['change_percent']}% "
        f"(new={report['new_items']}, removed={report['removed_items']}, "
        f"protocol_passed={report['protocol_passed']})"
    )

    if not decision["publish"]:
        append_diagnostics({
            "event": "post_skipped",
            "reason": decision["reason"],
            "change_percent": decision["change_percent"],
            "new_items": report["new_items"],
            "removed_items": report["removed_items"],
            "protocol_passed": report["protocol_passed"],
        })
        print(
            f"\n✅ Готово за {round(duration, 1)}с. checked/ и репозиторий обновлены, "
            f"опубликовано (файлы): {total_to_publish}. Пост в канал НЕ отправлен "
            f"(незначительное изменение)."
        )
        return 0

    # Единый пост обновления (ТЗ3 п.6): в DRY — формируется и показывается preview.
    tg_ok = send_telegram(report, file_meta)
    if not tg_ok:
        print("❌ Ошибка отправки в Telegram")
        return 1

    print(f"\n✅ Готово за {round(duration, 1)}с. Опубликовано: {total_to_publish}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
