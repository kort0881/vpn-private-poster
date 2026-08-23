#!/usr/bin/env python3
"""
Telegram-модуль контентного контура.

- publish_approved_post: публикация поста в канал + запись published.jsonl
  (анти-дубль между запусками).
- build_subscription_buttons: кнопки-ссылки на реальные файлы checked/
  (manifest.json).

Безопасность:
- токен никогда не печатается;
- HTML экранируется;
- длина ограничена;
- дубли публикаций исключаются через post_hash в data/published.jsonl.
"""
from __future__ import annotations

import html
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import requests

SCRIPT_DIR = Path(__file__).resolve().parent.parent
CHECKED_DIR = SCRIPT_DIR / "checked"
PUBLISHED_LOG = SCRIPT_DIR / "data" / "published.jsonl"

REPO_OWNER = "kort0881"
REPO_NAME = "vpn-private-poster"
BRANCH = "main"

MAX_MESSAGE_LENGTH = 4096

_sess = requests.Session()


def _bot_token() -> str:
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    if not token:
        raise RuntimeError("Не задан TELEGRAM_BOT_TOKEN")
    return token


def _channel_id() -> str:
    chat_id = os.getenv("TELEGRAM_PRIVATE_CHANNEL", "").strip()
    if not chat_id:
        raise RuntimeError("Не задан TELEGRAM_PRIVATE_CHANNEL")
    return chat_id


def _api(method: str, **kwargs) -> dict:
    url = f"https://api.telegram.org/bot{_bot_token()}/{method}"
    resp = _sess.post(url, json=kwargs, timeout=30)
    data = resp.json()
    if not data.get("ok"):
        raise RuntimeError(f"Telegram API {method}: {data.get('description')}")
    return data


def _escape(text: str) -> str:
    return html.escape(text, quote=False)


def _split_long(text: str, limit: int = MAX_MESSAGE_LENGTH) -> list[str]:
    if len(text) <= limit:
        return [text]
    parts = []
    while len(text) > limit:
        cut = text.rfind("\n", 0, limit)
        if cut < limit // 2:
            cut = limit
        parts.append(text[:cut])
        text = text[cut:]
    parts.append(text)
    return parts


def build_subscription_buttons() -> list[dict]:
    """
    Кнопки-ссылки на реальные файлы checked/ из manifest.json.
    Возвращает [{"text": ..., "url": ...}], максимум 8 кнопок.
    Один файл → кнопка «📥 Скачать подписку», несколько — по регионам.
    """
    manifest_path = CHECKED_DIR / "manifest.json"
    buttons: list[dict] = []
    if not manifest_path.exists():
        return buttons
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return buttons
    files = (manifest.get("files") or [])[:4]
    single = len(files) == 1
    for file_info in files:
        name = file_info.get("name", "")
        region = file_info.get("region", "")
        url = (
            f"https://raw.githubusercontent.com/"
            f"{REPO_OWNER}/{REPO_NAME}/{BRANCH}/checked/{name}"
        )
        if single:
            label = "📥 Скачать подписку"
        else:
            label = f"📥 {region} ({name})"
        buttons.append({"text": label, "url": url})
    return buttons


def build_post_buttons() -> list[dict]:
    """
    Кнопки для поста обновления: реальные файлы checked/ + опциональные
    «🛠 Инструкция» / «🛟 Резервный способ» / «📊 Статус проверки».
    Опциональные кнопки добавляются ТОЛЬКО при заданных TELEGRAM_*_URL —
    ссылки не выдумываются (ТЗ3: «не добавлять несуществующие ссылки»).
    """
    buttons = build_subscription_buttons()
    optional = (
        ("TELEGRAM_GUIDE_URL", "🛠 Инструкция"),
        ("TELEGRAM_BACKUP_URL", "🛟 Резервный способ"),
        ("TELEGRAM_STATUS_URL", "📊 Статус проверки"),
    )
    for env_name, label in optional:
        url = os.getenv(env_name, "").strip()
        if url:
            buttons.append({"text": label, "url": url})
    return buttons


def publish_post_with_buttons(post: str, buttons: list[dict] | None = None) -> bool:
    """
    Отправляет ОДИН пост в канал. Кнопки прикрепляются к сообщению
    (inline_keyboard, по 2 в ряд).
    """
    try:
        chat_id = _channel_id()
        _bot_token()
    except RuntimeError as exc:
        print(f"⚠️ {exc}")
        return False

    reply_markup = None
    if buttons:
        rows = [buttons[i:i + 2] for i in range(0, len(buttons), 2)]
        reply_markup = {"inline_keyboard": rows}

    try:
        for part in _split_long(post):
            _api(
                "sendMessage", chat_id=chat_id, text=part, parse_mode="HTML",
                disable_web_page_preview=True,
                reply_markup=reply_markup if part == post[:len(part)] else None,
            )
    except RuntimeError as exc:
        print(f"❌ {exc}")
        return False
    return True


def send_draft_to_admin(draft: dict, review: dict) -> bool:
    """Удалено: модерация админом не используется (решение владельца)."""
    raise RuntimeError("Модерация отключена по решению владельца")


def publish_approved_post(draft: dict) -> bool:
    """
    Публикует одобренный пост в закрытый канал.
    Возвращает False, если пост уже публиковался (дубль).
    """
    post = (draft.get("post") or "").strip()
    if not post:
        return False

    from src.content_review import post_hash, load_published_hashes
    hashes = load_published_hashes()
    h = post_hash(post)
    if h in hashes:
        print("ℹ️  Пост уже публиковался — пропускаем (анти-дубль)")
        return False

    try:
        chat_id = _channel_id()
        _bot_token()
    except RuntimeError as exc:
        print(f"⚠️ {exc}")
        return False

    buttons = build_subscription_buttons()
    reply_markup = None
    if buttons:
        rows = [buttons[i:i + 2] for i in range(0, len(buttons), 2)]
        reply_markup = {"inline_keyboard": rows}

    try:
        for part in _split_long(post):
            _api("sendMessage", chat_id=chat_id, text=part, parse_mode="HTML",
                 disable_web_page_preview=True,
                 reply_markup=reply_markup if part == post[:len(part)] else None)
    except RuntimeError as exc:
        print(f"❌ {exc}")
        return False

    record = {
        "post_hash": h,
        "category": draft.get("category"),
        "title": draft.get("title"),
        "published_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "model": draft.get("model"),
        "source_hashes": [],
        "checked_at": draft.get("checked_at"),
    }
    PUBLISHED_LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(PUBLISHED_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    print("✅ Пост опубликован и записан в data/published.jsonl")
    return True
