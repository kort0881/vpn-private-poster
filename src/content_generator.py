#!/usr/bin/env python3
"""
Генерация контентных постов для закрытого Telegram-канала.

- Читает data/current_report.json.
- Выбирает рубрику по событию (ТЗ1): update / status / problem / guide /
  backup / security / news / digest.
- Загружает промт рубрики + system.md.
- Вызывает единый AIClient, парсит JSON-ответ.
- Сохраняет черновик в data/drafts/<timestamp>.json.
- Проверяет черновик (src.content_review) и отправляет администратору.

Команды:
  python -m src.content_generator              # авто-рубрика по событию
  python -m src.content_generator --dry-run    # без отправки в Telegram
  python -m src.content_generator --category guide --topic "Как обновить подписку на Android"
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent.parent
PROMPTS_DIR = SCRIPT_DIR / "content" / "prompts"
REPORT_PATH = SCRIPT_DIR / "data" / "current_report.json"
DRAFTS_DIR = SCRIPT_DIR / "data" / "drafts"

sys.path.insert(0, str(SCRIPT_DIR))

from src.ai_client import AIClient, AIClientError  # noqa: E402
from src.content_review import review_draft, save_review  # noqa: E402

CATEGORIES = ("update", "status", "problem", "guide", "backup", "security", "news", "digest")


def pick_category(report: dict) -> str | None:
    """
    Выбирает рубрику по событию. Возвращает None, если публиковать нечего.
    """
    if not report or report.get("publish_allowed") is not True:
        return None
    if (report.get("protocol_passed") or 0) == 0:
        return None

    new_items = report.get("new_items") or 0
    removed_items = report.get("removed_items") or 0
    critical_drop = report.get("critical_drop") is True
    failures = report.get("failures") or {}
    protocol_failures = failures.get("protocol") or 0
    checked = (report.get("protocol_passed") or 0) + protocol_failures

    if new_items > 0 or removed_items > 0:
        return "update"
    if critical_drop:
        return "backup"
    if checked and protocol_failures > checked * 0.5:
        return "backup"
    return None  # изменений нет — ничего не публикуем


def build_report_context(report: dict) -> dict:
    """Безопасный срез отчёта для AI: только агрегаты, без items/хэшей."""
    items = report.get("items") or []
    latencies = [
        float(i["latency"]) for i in items
        if isinstance(i.get("latency"), (int, float)) and float(i["latency"]) > 0
    ]
    avg_latency = round(sum(latencies) / len(latencies), 1) if latencies else None

    by_region = report.get("by_region") or {}
    best_region = max(by_region, key=by_region.get) if by_region else "—"

    return {
        "total_found": report.get("total_found"),
        "parsed": report.get("parsed"),
        "dns_passed": report.get("dns_passed"),
        "tcp_passed": report.get("tcp_passed"),
        "protocol_passed": report.get("protocol_passed"),
        "published_count": report.get("published_count"),
        "new_items": report.get("new_items"),
        "removed_items": report.get("removed_items"),
        "stable_items": report.get("stable_items"),
        "critical_drop": report.get("critical_drop"),
        "publish_allowed": report.get("publish_allowed"),
        "by_region": by_region,
        "by_protocol": report.get("by_protocol"),
        "by_check_level": report.get("by_check_level"),
        "failures": report.get("failures"),
        "best_region": best_region,
        "average_latency_ms": avg_latency,
        "checked_at": report.get("checked_at"),
    }


def load_prompt(category: str) -> str:
    prompt_file = PROMPTS_DIR / f"{category}.md"
    if not prompt_file.exists():
        raise FileNotFoundError(f"Промт не найден: {prompt_file}")
    return prompt_file.read_text(encoding="utf-8")


def build_messages(category: str, context: dict, topic: str | None) -> list[dict]:
    system = (PROMPTS_DIR / "system.md").read_text(encoding="utf-8")
    rubric = load_prompt(category)
    user = (
        f"Рубрика: {category}\n"
        f"Тема (если задана): {topic or '—'}\n\n"
        f"Данные отчёта (JSON):\n{json.dumps(context, ensure_ascii=False, indent=2)}\n\n"
        f"Правила рубрики:\n{rubric}\n\n"
        "Верни JSON по формату из системного промта."
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="Генератор контентных постов")
    parser.add_argument("--dry-run", action="store_true",
                        help="не отправлять черновик в Telegram")
    parser.add_argument("--category", choices=CATEGORIES, default=None,
                        help="принудительная рубрика")
    parser.add_argument("--topic", default=None,
                        help="тема для problem/guide")
    args = parser.parse_args()

    if not REPORT_PATH.exists():
        print("❌ Нет data/current_report.json — сначала запусти poster_private.py")
        return 1

    report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))

    category = args.category or pick_category(report)
    if category is None:
        print("ℹ️  Существенных изменений нет — пост не публикуем (по ТЗ1)")
        return 0

    if category in ("problem", "guide") and not args.topic:
        print(f"❌ Для рубрики {category} нужен --topic")
        return 1

    context = build_report_context(report)

    try:
        client = AIClient(chain="content")
    except AIClientError as exc:
        print(f"❌ {exc}")
        return 1

    messages = build_messages(category, context, args.topic)
    print(f"🤖 Генерация поста (рубрика: {category})...")

    try:
        draft, model = client.generate_json(messages)
    except AIClientError as exc:
        print(f"❌ AI: {exc}")
        return 1

    draft.setdefault("category", category)
    draft.setdefault("model", model)
    draft.setdefault("checked_at", report.get("checked_at"))
    draft.setdefault("sources", ["own_report"])
    if not draft.get("post") or not draft.get("post").strip():
        print("ℹ️  AI сообщил об отсутствии события — пост не создаём")
        return 0

    DRAFTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    draft_path = DRAFTS_DIR / f"{ts}.json"
    draft_path.write_text(
        json.dumps(draft, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"💾 Черновик сохранён: {draft_path}")

    review = review_draft(draft, report=report)
    save_review(draft_path, review)
    print(f"🔎 Проверка: {review['status']} (risk={review['risk_level']})")
    for problem in review["problems"]:
        print(f"   ⚠️ {problem}")

    if not review["safe_to_publish"]:
        print("🚫 Черновик НЕ публикуется (needs_review/rejected)")
        return 0

    if args.dry_run:
        print("[DRY] Черновик готов, публикация пропущена.")
        print(f"---\n{draft.get('post', '')}\n---")
        return 0

    # Авто-публикация в канал (по решению владельца, без подтверждения)
    from src.telegram_content import publish_approved_post  # noqa: E402
    ok = publish_approved_post(draft)
    if not ok:
        print("❌ Не удалось опубликовать пост (дубль или ошибка)")
        return 1
    print("✅ Пост опубликован в канал")
    return 0


if __name__ == "__main__":
    sys.exit(main())
