#!/usr/bin/env python3
"""
Поллер кнопок подтверждения постов (живой процесс).

Слушает callback-кнопки в админском чате:
  ✅ Опубликовать      → публикация поста в канал + запись published.jsonl
  ✏️ Перегенерировать  → пометка черновика на перегенерацию
  🗑 Отклонить          → пометка черновика отклонённым

Запуск (долгоиграющий процесс, systemd):
  python -m src.approval_bot

Только администратор (TELEGRAM_ADMIN_CHAT_ID) может подтверждать.
Черновики ищутся в data/drafts/<draft_id>.json.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import requests

SCRIPT_DIR = Path(__file__).resolve().parent.parent
DRAFTS_DIR = SCRIPT_DIR / "data" / "drafts"
PUBLISHED_LOG = SCRIPT_DIR / "data" / "published.jsonl"

POLL_TIMEOUT = 30
MAX_UPDATES = 100

_sess = requests.Session()


def _api(method: str, **kwargs) -> dict:
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    if not token:
        raise RuntimeError("Не задан TELEGRAM_BOT_TOKEN")
    url = f"https://api.telegram.org/bot{token}/{method}"
    resp = _sess.post(url, json=kwargs, timeout=60)
    data = resp.json()
    if not data.get("ok"):
        raise RuntimeError(f"Telegram API {method}: {data.get('description')}")
    return data


def _admin_id() -> int:
    raw = os.getenv("TELEGRAM_ADMIN_CHAT_ID", "").strip()
    if not raw:
        raise RuntimeError("Не задан TELEGRAM_ADMIN_CHAT_ID")
    return int(raw)


def _draft_path(draft_id: str) -> Path:
    return DRAFTS_DIR / f"{draft_id}.json"


def _mark(draft_id: str, suffix: str) -> None:
    """Пишет data/drafts/<draft_id>.<suffix> — маркер решения админа."""
    src = _draft_path(draft_id)
    if not src.exists():
        return
    marker = DRAFTS_DIR / f"{draft_id}.{suffix}"
    marker.write_text(
        json.dumps({"draft_id": draft_id, "decision": suffix,
                    "at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}),
        encoding="utf-8",
    )


def handle_callback(query: dict) -> str | None:
    """Обрабатывает callback_query. Возвращает текст ответа или None."""
    data = query.get("data") or ""
    user_id = (query.get("from") or {}).get("id")
    try:
        admin_id = _admin_id()
    except RuntimeError:
        admin_id = None

    if admin_id is not None and user_id != admin_id:
        return "⛔ Только для администратора"

    if not data.startswith("content:"):
        return None
    action, draft_id = data.split(":", 2)[1], data.split(":", 2)[2]

    if action == "approve":
        draft_path = _draft_path(draft_id)
        if not draft_path.exists():
            return "❌ Черновик не найден"
        draft = json.loads(draft_path.read_text(encoding="utf-8"))
        sys.path.insert(0, str(SCRIPT_DIR))
        from src.telegram_content import publish_approved_post
        if publish_approved_post(draft):
            _mark(draft_id, "approved")
            return "✅ Опубликовано в канал"
        return "❌ Не опубликовано (дубль или ошибка)"

    if action == "regenerate":
        _mark(draft_id, "regenerate")
        return "✏️ Черновик помечен на перегенерацию"

    if action == "reject":
        _mark(draft_id, "rejected")
        return "🗑 Черновик отклонён"

    return None


def main() -> int:
    print("🤖 approval_bot: слушаю кнопки админа...")
    offset = 0
    while True:
        try:
            updates = _api("getUpdates", offset=offset, timeout=POLL_TIMEOUT,
                           allowed_updates=["callback_query"])
        except RuntimeError as exc:
            print(f"⚠️ {exc}", flush=True)
            time.sleep(5)
            continue
        except requests.exceptions.RequestException as exc:
            print(f"⚠️ сеть: {exc}", flush=True)
            time.sleep(5)
            continue

        for update in updates.get("result", []):
            update_id = update.get("update_id")
            if update_id is not None:
                offset = update_id + 1

            query = update.get("callback_query")
            if not query:
                continue
            try:
                reply = handle_callback(query)
                if reply:
                    _api("answerCallbackQuery",
                         callback_query_id=query.get("id"),
                         text=reply, show_alert=False)
                    print(f"💬 {reply}", flush=True)
            except RuntimeError as exc:
                print(f"⚠️ обработка кнопки: {exc}", flush=True)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nОстановлен.")
        sys.exit(0)
