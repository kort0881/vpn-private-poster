#!/usr/bin/env python3
"""
PRIVATE VPN POSTER — v34.1 (фикс UnicodeError при резолве кривых hostname)

Изменения относительно v34:
- _resolve_ip_cached(): добавлен перехват UnicodeError (IDNA-кодирование
  падает на слишком длинных/кривых hostname: "UnicodeError: label too
  long"). Раньше ловился только OSError, из-за чего один битый хост в
  списке источников валил весь процесс проверки (traceback в GitHub
  Actions). Теперь такой хост просто считается неразрешённым (регион
  "Unknown"), проверка остальных ключей продолжается.
- get_region_from_key(): добавлена дополнительная защита try/except
  вокруг вызова _resolve_ip_cached()/_is_ip() и вокруг host.lower().split(".")
  на случай экзотических ошибок кодирования, не покрытых внутри самих
  функций.

Изменения относительно v33 (сохранены из v34):
1. checked_count: в отчёт добавлено реальное количество проверенных
   ключей (после обрезки max_keys_to_check). Поле total_found
   переименовано по смыслу в raw_lines_found — используется только для
   диагностики, НЕ для текста поста.
2. should_publish_update(): пост в Telegram публикуется только при
   существенном изменении (new_items>=3 ИЛИ removed_items>=10 ИЛИ
   |Δprotocol_passed|>=20% ИЛИ critical_drop=true). checked/ и push в
   GitHub всё равно обновляются каждый прогон.
3. xray_check_key(): multi-probe — fallback на резервные контрольные URL
   срабатывает не только при исключении, но и при плохом HTTP-статусе.
4. get_region_from_key(): регион определяется по IP (опциональный GeoIP
   через GEOIP_DB_PATH), а не только по TLD домена. Если определить
   регион нельзя — bucket "Unknown", а не "Other".

Изменения относительно v32 (сохранены):
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
XRAY_ASSETS_DIR = os.environ.get("XRAY_ASSETS_DIR", "")
XRAY_TEST_URL = os.environ.get("XRAY_TEST_URL", "https://api.ipify.org?format=json")
XRAY_TEST_URL_FALLBACK = os.environ.get("XRAY_TEST_URL_FALLBACK", "http://1.1.1.1")
XRAY_TEST_URL_FALLBACK2 = os.environ.get(
    "XRAY_TEST_URL_FALLBACK2", "https://cp.cloudflare.com/generate_204"
)
MAX_XRAY_WORKERS = 3

MIN_NEW_ITEMS_FOR_POST = int(os.environ.get("MIN_NEW_ITEMS_FOR_POST", "3"))
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


def is_supported_protocol(value: str) -> bool:
    return bool(SCHEME_PATTERN.match(value.strip()))


def clean_key(raw: str) -> str | None:
    if raw is None:
        return None
    k = str(raw)
    k = re.split(r"[ \t]+", k.strip(), maxsplit=1)[0]
    if not k:
        return None
    k = html.unescape(k)
    k = k.replace("&amp;", "&")
    if not k or len(k) < 12:
        return None
    return k


def parse_key(key: str) -> dict | None:
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

    if protocol == "vmess":
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
    payload = path.strip("/")
    try:
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
    return hashlib.sha256(key.encode("utf-8", errors="ignore")).hexdigest()


def mask_key(key: str, show_chars: int = 6) -> str:
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
    seen: dict[str, None] = {}
    dups = 0
    for k in keys:
        if k in seen:
            dups += 1
            continue
        seen[k] = None
    return list(seen.keys()), dups


def extract_host_port(key: str) -> tuple[str | None, int | None]:
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
    """
    DNS resolve с простым in-memory кэшем на один запуск.

    v34.1: помимо socket.gaierror/OSError ловим UnicodeError — он
    возникает при кодировании кривого/слишком длинного hostname в IDNA
    (например, обрезанный или битый host из конфигурации: "UnicodeError:
    label too long"). Раньше это не перехватывалось и валило весь процесс
    проверки (traceback в GitHub Actions на одном плохом ключе из 1000).
    """
    if host in _dns_cache:
        return _dns_cache[host]
    try:
        ip = socket.gethostbyname(host)
    except (socket.gaierror, UnicodeError, OSError):
        ip = None
    _dns_cache[host] = ip
    return ip


def get_region_from_key(key: str) -> str:
    host, _ = extract_host_port(key)
    if not host:
        return "Unknown"

    try:
        ip = host if _is_ip(host) else _resolve_ip_cached(host)
    except (socket.gaierror, UnicodeError, OSError):
        # Дополнительная защита на случай экзотических ошибок кодирования
        # хоста, не покрытых внутри _resolve_ip_cached/_is_ip.
        ip = None

    if _geoip_reader and ip:
        try:
            resp = _geoip_reader.country(ip)
            code = resp.country.iso_code
            if code:
                return COUNTRY_TO_REGION.get(code, "Other")
        except Exception:
            pass

    if not _is_ip(host):
        try:
            parts = host.lower().split(".")
        except (UnicodeError, AttributeError):
            return "Unknown"
        if len(parts) >= 2 and parts[-1] in TLD_REGION:
            return TLD_REGION[parts[-1]]

    return "Unknown"


def dns_resolve(host: str) -> bool:
    try:
        socket.getaddrinfo(host, 80, socket.AF_INET, socket.SOCK_STREAM, 0, socket.AI_ADDRCONFIG)
        return True
    except (socket.gaierror, UnicodeError, OSError):
        return False


def tcp_check(host: str, port: int, timeout: float) -> float | None:
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
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def safe_error(exc: Exception) -> str:
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
    if "pbk" in query or "sid" in query:
        return True
    sec = (query.get("security") or [""])[0]
    if sec in ("reality", "tls"):
        return True
    if "flow" in query and (query.get("encryption") or [""])[0] == "none":
        return True
    return False


def _probe(url: str, proxies: dict, timeout: float) -> tuple[int | None, str | None]:
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
        for url in probe_urls:
            start = time.time()
            status, err = _probe(url, proxies, timeout)
            elapsed = time.time() - start
            if status is not None and 200 <= status < 400:
                return True, round(elapsed, 3), None
            last_err = err or (f"http_{status}" if status is not None else "unknown_error")
            # v34.2: connection_error/timeout — проблема самого туннеля
            # (локальный прокси Xray не отвечает или обрыв на стороне
            # сервера), а не конкретного контрольного сайта. Пробовать
            # оставшиеся URL через тот же сломанный туннель бессмысленно
            # и утраивает время ожидания на каждый мёртвый ключ — именно
            # это подняло длительность прогона с 813с до 1130с.
            # Multi-probe остаётся полезен только при плохом HTTP-статусе
            # (например http_503) — там смена адресата реально помогает.
            if last_err in ("connection_error", "timeout"):
                break

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


def check_one(
    key: str,
    settings: dict,
    with_protocol: bool = True,
) -> dict | None:
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

    if not dns_resolve(p["host"]):
        return {**base, "check_level": "dns", "status": "dead", "latency": None,
                "error_code": "dns_failed", "levels_passed": ["parse"]}

    rtt = tcp_check(p["host"], p["port"], settings["tcp_timeout"])
    if rtt is None:
        return {**base, "check_level": "tcp", "status": "dead", "latency": None,
                "error_code": "tcp_failed", "levels_passed": ["parse", "dns"]}

    if p["protocol"] in ("hysteria2", "hy2"):
        return {**base, "check_level": "tcp_only", "status": "working", "latency": rtt,
                "error_code": "hysteria2_udp_not_supported",
                "levels_passed": ["parse", "dns", "tcp"]}

    result = {**base, "check_level": "tcp", "status": "working", "latency": rtt,
              "error_code": None, "levels_passed": ["parse", "dns", "tcp"]}

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
    total = len(keys)
    results: list[dict] = []

    print(f"\n🔍 Проверка {total} ключей ({settings['max_workers']} потоков, TCP-таймаут {settings['tcp_timeout']}с)...")

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


def rotate_reports() -> None:
    os.makedirs(REPORT_DIR, exist_ok=True)
    if os.path.exists(CURRENT_REPORT):
        try:
            shutil.copy2(CURRENT_REPORT, PREVIOUS_REPORT)
        except OSError as exc:
            print(f"⚠️  Не удалось сохранить previous_report: {exc}")


def append_diagnostics(entry: dict) -> None:
    os.makedirs(REPORT_DIR, exist_ok=True)
    entry.setdefault("ts", datetime.now(timezone.utc).isoformat(timespec="seconds"))
    try:
        with open(DIAGNOSTICS_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError as exc:
        print(f"⚠️  Не удалось записать diagnostics: {exc}")


def write_report(report: dict) -> None:
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
        "checked_count": checked_count,
        "raw_lines_found": raw_lines_found,
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


def replace_hosts_in_key(key: str, new_host: str) -> str:
    key = re.sub(r"@([^:@\s]+)", f"@{new_host}", key)
    key = re.sub(r"(server|add)=([^&\s]+)", rf"\1={new_host}", key)
    return key


def prepare_keys_for_publish(verified_keys: list[tuple[str, dict]], settings: dict) -> list[tuple[str, dict]]:
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
    if not file_meta:
        return False
    os.makedirs(CHECKED_DIR, exist_ok=True)

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
        new_names = {m["name"] for m in file_meta}
        for old in os.listdir(CHECKED_DIR):
            if old.endswith("_sub.txt") and old not in new_names:
                try:
                    os.remove(os.path.join(CHECKED_DIR, old))
                except OSError:
                    pass
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


def _redact(text: str) -> str:
    if GH_TOKEN and GH_TOKEN in text:
        text = text.replace(GH_TOKEN, "***")
    return text


def push_to_repo() -> bool:
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
    if not BOT_TOKEN or not CHANNEL_ID:
        print("⚠️  TELEGRAM_BOT_TOKEN или TELEGRAM_PRIVATE_CHANNEL не заданы")
        return False
    stats = publish_update(report, file_meta, dry_run=DRY)
    if DRY:
        return True
    return bool(stats["published"] or stats["skipped"])


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


def main() -> int:
    settings = load_settings()
    version = "PRIVATE POSTER v34.1 (фикс UnicodeError на кривых hostname)"
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
            if settings["keep_previous_on_failure"]:
                print("🛡️ checked/ не тронут (keep_previous_on_failure=true)")
            duration = time.time() - start
            report = build_report(results, raw_lines_found, checked_count, parsed, duration, False, 0, settings)
            write_report(report)
            return 1

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

    duration = time.time() - start
    report = build_report(results, raw_lines_found, checked_count, parsed, duration, True, total_to_publish, settings)
    write_report(report)

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

    tg_ok = send_telegram(report, file_meta)
    if not tg_ok:
        print("❌ Ошибка отправки в Telegram")
        return 1

    print(f"\n✅ Готово за {round(duration, 1)}с. Опубликовано: {total_to_publish}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
