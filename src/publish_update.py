#!/usr/bin/env python3
"""
Единая публикация технического поста после проверки (ТЗ3, п.6).

publish_update(report, file_meta):
1. Формирует пост: AI-версия (если AI доступен и пост проходит
   src.content_review) или безопасный fallback-шаблон.
2. Печатает служебные строки:
   CONTENT_MODE / POST_TYPE / POST_TEMPLATE / OLD_POST_FORMAT /
   POST PREVIEW / TELEGRAM_MESSAGES_TO_CHANNEL.
3. Отправляет ОДИН пост в канал + кнопки реальных файлов checked/
   (плюс опциональные кнопки Инструкция/Резервный/Статус — только
   при заданных TELEGRAM_*_URL).
4. Записывает post_hash (content_key) в data/published.jsonl.
5. Не публикует повторно при идентичном результате проверки.

Старый формат «Private VPN Subscriptions» здесь НЕ используется:
старая обложка и отдельное сообщение «📋 Файлы подписок» убраны.

Безопасность:
- AI получает только data/current_report.json и безопасные метаданные;
- числа не выдумываются (review сверяет с отчётом);
- preview проверяется на токены/UUID/полные конфигурации;
- ссылки в кнопках — только реальные файлы checked/ или заданные URL.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src import content_review as _cr
from src import telegram_content as _tg

SCRIPT_DIR = Path(__file__).resolve().parent.parent
PROMPTS_DIR = SCRIPT_DIR / "content" / "prompts"
PUBLISHED_LOG = SCRIPT_DIR / "data" / "published.jsonl"

OLD_POST_TITLE = "Private VPN Subscriptions"
UNKNOWN_REGIONS = ("Other", "Unknown", "")

MAX_PREVIEW_CHARS = 500


def _format_checked_at(checked_at: str | None) -> str:
    """ISO-дата → '23.08.2026, 09:48 MSK'. При ошибке — исходная строка."""
    if not checked_at:
        return "—"
    try:
        raw = str(checked_at).replace("Z", "+00:00")
        dt = datetime.fromisoformat(raw)
        msk = dt.astimezone(timezone(timedelta(hours=3)))
        return msk.strftime("%d.%m.%Y, %H:%M MSK")
    except (ValueError, TypeError):
        return str(checked_at)


def region_display(region: str | None) -> str:
    """'Other' → 'Region unknown' (ТЗ3: тест 7 — вместо неинформативного Other)."""
    return "Region unknown" if (region or "Other") in UNKNOWN_REGIONS else region


def _content_key(report: dict, file_meta: list[dict] | None) -> str:
    """
    Стабильный ключ содержимого поста: одинаковый при идентичном результате
    проверки. Используется как post_hash в data/published.jsonl (анти-дубль).
    """
    payload = {
        "protocol_passed": report.get("protocol_passed", 0),
        "new_items": report.get("new_items", 0),
        "removed_items": report.get("removed_items", 0),
        "stable_items": report.get("stable_items", 0),
        "files": sorted(
            (str(m.get("name", "")), int(m.get("count", 0)))
            for m in (file_meta or [])
        ),
    }
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def build_fallback_post(report: dict, file_meta: list[dict] | None) -> dict:
    """
    Безопасный fallback-шаблон (ТЗ3, п.5): новый формат, без старого
    заголовка, только числа из отчёта. Не требует AI.
    """
    file_count = len(file_meta or [])
    by_region = report.get("by_region") or {}
    known_regions = [r for r in by_region if r not in UNKNOWN_REGIONS]
    region_text = ", ".join(known_regions[:3]) if known_regions else "Region unknown"

    post = (
        "🔐 Обновление подключений\n\n"
        f"Проверено: {report.get('total_found', 0)}\n"
        f"Полную проверку прошли: {report.get('protocol_passed', 0)}\n"
        f"Опубликовано файлов: {file_count}\n\n"
        f"🌐 Регион: {region_text}\n"
        f"🕒 Проверено: {_format_checked_at(report.get('checked_at'))}\n\n"
        "Результат актуален на момент проверки. Работоспособность зависит "
        "от оператора, региона и сети.\n\n"
        "Обновите подписку и попробуйте профиль из сегодняшнего списка."
    )
    return {
        "category": "update",
        "title": "Обновление подключений",
        "post": post,
        "buttons": [{"label": "📥 Скачать подписку", "action": "subscriptions"}],
        "checked_at": report.get("checked_at"),
        "sources": ["own_report"],
        "limitations": ["Результат зависит от оператора, региона и сети."],
    }


def _build_ai_messages(context: dict, file_meta: list[dict] | None) -> list[dict]:
    """Сообщения для AI: system.md + рубрика subscription_update + данные отчёта."""
    system = (PROMPTS_DIR / "system.md").read_text(encoding="utf-8")
    rubric = (PROMPTS_DIR / "subscription_update.md").read_text(encoding="utf-8")
    user = (
        f"Данные отчёта (JSON):\n{json.dumps(context, ensure_ascii=False, indent=2)}\n\n"
        f"Файлы подписок (только имена): "
        f"{[m.get('name') for m in (file_meta or [])]}\n\n"
        f"Правила рубрики:\n{rubric}\n\n"
        "Верни JSON по формату из системного промта."
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]


def _build_ai_draft(report: dict, file_meta: list[dict] | None) -> dict | None:
    """
    AI-версия поста. Возвращает draft или None, если AI недоступен,
    вернул пустой пост или не-JSON.
    """
    if not os.getenv("AI_API_KEY", "").strip():
        return None
    try:
        from src.content_generator import build_report_context
        from src.ai_client import AIClient, AIClientError

        context = build_report_context(report)
        client = AIClient(chain="content")
        draft, model = client.generate_json(_build_ai_messages(context, file_meta))
    except (AIClientError, FileNotFoundError, OSError, ValueError) as exc:
        print(f"⚠️ AI недоступен — используем fallback: {exc}")
        return None

    draft.setdefault("category", "update")
    draft.setdefault("model", model)
    draft.setdefault("checked_at", report.get("checked_at"))
    draft.setdefault("sources", ["own_report"])
    post = (draft.get("post") or "").strip()
    if not post:
        print("⚠️ AI вернул пустой пост — используем fallback")
        return None
    return draft


def _preview_safe(text: str) -> bool:
    """Preview не должен содержать токены/UUID/конфигурации/старый заголовок."""
    if OLD_POST_TITLE in text:
        return False
    for scheme in ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://"):
        if scheme in text:
            return False
    if _cr._check_secrets(text):
        return False
    return True


def _write_published_record(record: dict) -> None:
    PUBLISHED_LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(PUBLISHED_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def publish_update(
    report: dict,
    file_meta: list[dict] | None = None,
    dry_run: bool = False,
) -> dict:
    """
    ТЗ3, п.6: одна функция публикации технического поста.

    Возвращает статистику:
    {"template": "ai"|"fallback", "messages_to_channel": N,
     "published": bool, "skipped": bool}
    """
    stats = {
        "template": "fallback",
        "messages_to_channel": 0,
        "published": False,
        "skipped": False,
    }
    print("CONTENT_MODE: enabled")
    print("POST_TYPE: subscription_update")
    print("OLD_POST_FORMAT: disabled")

    draft = _build_ai_draft(report, file_meta)
    template = "ai" if draft else "fallback"
    if draft:
        review = _cr.review_draft(draft, report=report)
        if not review["safe_to_publish"]:
            print("⚠️ AI-пост не прошёл локальную проверку — используем безопасный fallback")
            for problem in review["problems"][:5]:
                print(f"   ⚠️ {problem}")
            draft = None
            template = "fallback"

    if draft is None:
        draft = build_fallback_post(report, file_meta)

    post = (draft.get("post") or "").strip()
    if not post:
        print("❌ Пост пуст — публикация невозможна")
        return stats

    stats["template"] = template
    print(f"POST_TEMPLATE: {template}")
    print("POST PREVIEW:")
    print(post[:MAX_PREVIEW_CHARS])

    if not _preview_safe(post):
        print("❌ POST PREVIEW содержит недопустимые данные — публикация отменена")
        return stats

    # Анти-дубль: одинаковый результат проверки не публикуется повторно
    key = _content_key(report, file_meta)
    if key in _cr.load_published_hashes(PUBLISHED_LOG):
        print("ℹ️  Такой результат уже публиковался — пропускаем (анти-дубль)")
        stats["skipped"] = True
        return stats

    if dry_run:
        print("[DRY] Пост готов, отправка в канал пропущена.")
        print(f"[DRY] post_hash записывается: {key}")
    else:
        if not os.getenv("TELEGRAM_BOT_TOKEN", "").strip() or not os.getenv(
            "TELEGRAM_PRIVATE_CHANNEL", ""
        ).strip():
            print("⚠️  TELEGRAM_BOT_TOKEN или TELEGRAM_PRIVATE_CHANNEL не заданы")
            return stats
        buttons = _tg.build_post_buttons()
        ok = _tg.publish_post_with_buttons(post, buttons)
        if not ok:
            print("❌ Не удалось отправить пост в канал")
            return stats
        stats["messages_to_channel"] = 1
        stats["published"] = True

    record = {
        "post_hash": key,
        "category": draft.get("category"),
        "title": draft.get("title"),
        "published_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "model": draft.get("model"),
        "source_hashes": [],
        "checked_at": draft.get("checked_at"),
        "template": template,
    }
    _write_published_record(record)

    if stats["published"]:
        print("✅ Опубликован один основной пост обновления + кнопки файлов")
        print("TELEGRAM_MESSAGES_TO_CHANNEL: 1")
    else:
        print("TELEGRAM_MESSAGES_TO_CHANNEL: 0")
    return stats
