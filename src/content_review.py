#!/usr/bin/env python3
"""
Проверка AI-черновиков перед публикацией.

Проверяет: заголовок, текст, дату, источники, длину, подозрительные URL,
токены, UUID, пароли, приватные ключи, запрещённые формулировки,
опасные команды, неподтверждённые числа, дубли published.jsonl.

По умолчанию safe_to_publish=false.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent.parent
PUBLISHED_LOG = SCRIPT_DIR / "data" / "published.jsonl"

FORBIDDEN_PHRASES = [
    "гарантированно",
    "навсегда",
    "100% анонимность",
    "полная анонимность",
    "работает у всех",
    "вечный vpn",
    "невозможно заблокировать",
    "лучший vpn в мире",
    "никогда не заблокируют",
    "мы гарантируем",
]

SECRET_PATTERNS = [
    re.compile(r"\bsk-[A-Za-z0-9]{16,}"),        # OpenAI-стиль ключи
    re.compile(r"\bghp_[A-Za-z0-9]{20,}"),        # GitHub PAT
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),  # Slack
    re.compile(r"\bAIza[0-9A-Za-z_-]{20,}"),       # Google
    re.compile(r"\b-----BEGIN [A-Z ]*PRIVATE KEY-----"),  # приватные ключи
    re.compile(r"\b[0-9]{8,10}:[A-Za-z0-9_-]{30,}"),      # Telegram bot token
    re.compile(
        r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
        re.IGNORECASE,
    ),  # UUID (vless id)
]

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+")
DANGEROUS_CMDS = [
    "rm -rf", r"curl.*\|.*sh", r"wget.*\|.*sh", "chmod 777",
    "sudo su", "mkfs", "dd if=", "> /dev/sda", ":(){", "shutdown",
]

MAX_MESSAGE_LENGTH = 4096  # лимит Telegram


def post_hash(post: str) -> str:
    return hashlib.sha256(post.encode("utf-8", errors="ignore")).hexdigest()


def load_published_hashes(path: Path | str | None = None) -> set[str]:
    """Хэши уже опубликованных постов (data/published.jsonl)."""
    path = Path(path) if path else PUBLISHED_LOG
    hashes: set[str] = set()
    if not path.exists():
        return hashes
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            h = record.get("post_hash")
            if h:
                hashes.add(str(h))
    except OSError:
        pass
    return hashes


def _check_length(text: str) -> list[str]:
    if len(text) > MAX_MESSAGE_LENGTH:
        return [f"сообщение {len(text)} > {MAX_MESSAGE_LENGTH} символов (лимит Telegram)"]
    return []


def _check_secrets(text: str) -> list[str]:
    problems = []
    for pattern in SECRET_PATTERNS:
        match = pattern.search(text)
        if match:
            problems.append(f"найден секрет/идентификатор: {pattern.pattern[:40]}...")
    return problems


def _check_forbidden(text: str) -> list[str]:
    low = text.lower()
    return [f"запрещённая формулировка: «{phrase}»"
            for phrase in FORBIDDEN_PHRASES if phrase in low]


def _check_urls(text: str) -> list[str]:
    problems = []
    for url in URL_PATTERN.findall(text):
        if url.startswith("http://") and "localhost" not in url:
            problems.append(f"http-ссылка без TLS: {url[:60]}")
        if "://" in url and "." not in url.split("://")[1].split("/")[0]:
            problems.append(f"подозрительный URL: {url[:60]}")
    return problems


def _check_dangerous_commands(text: str) -> list[str]:
    low = text.lower()
    return [f"опасная команда: {cmd}" for cmd in DANGEROUS_CMDS
            if re.search(cmd, low)]


def _check_unverified_numbers(text: str, report: dict | None) -> list[str]:
    """Числа, которых нет в отчёте, — подозрительны (AI мог выдумать)."""
    if not report:
        return []
    report_text = json.dumps(report, ensure_ascii=False)
    numbers = set(re.findall(r"\d{2,}", text))
    problems = []
    for num in sorted(numbers):
        if num not in report_text:
            problems.append(f"число «{num}» не подтверждено отчётом")
            break  # одного достаточно для needs_review
    return problems


def _check_workability_claims(text: str) -> list[str]:
    """Утверждения о работоспособности без оговорок."""
    low = text.lower()
    problems = []
    if re.search(r"работает\s+у\s+всех", low):
        problems.append("утверждение «работает у всех»")
    if re.search(r"(?:точно|стопроцентно|100%)\s+работает", low):
        problems.append("утверждение о 100% работоспособности")
    return problems


def review_draft(
    draft: dict,
    report: dict | None = None,
    published_path: Path | str | None = None,
) -> dict:
    """
    Проверяет черновик. Возвращает dict вида:
    {
      "status": "approved|needs_review|rejected",
      "risk_level": "low|medium|high",
      "problems": [],
      "required_changes": [],
      "safe_to_publish": false
    }
    """
    problems: list[str] = []
    required_changes: list[str] = []

    post = (draft.get("post") or "").strip()
    title = (draft.get("title") or "").strip()
    checked_at = draft.get("checked_at") or ""
    sources = draft.get("sources") or []
    category = draft.get("category") or ""

    if not title:
        problems.append("нет заголовка")
        required_changes.append("добавить заголовок")
    if not post:
        problems.append("нет текста поста")
        required_changes.append("сгенерировать текст поста")
    if not checked_at:
        problems.append("нет даты проверки (checked_at)")
        required_changes.append("указать checked_at")
    if not sources:
        problems.append("нет источников (sources)")
        required_changes.append("указать источники")
    if not category:
        problems.append("нет категории")
        required_changes.append("указать категорию")

    if post:
        problems += _check_length(post)
        problems += _check_secrets(post + " " + title)
        problems += _check_forbidden(post + " " + title)
        problems += _check_urls(post)
        problems += _check_dangerous_commands(post)
        problems += _check_workability_claims(post)
        problems += _check_unverified_numbers(post, report)

    # Дубли уже опубликованных постов
    hashes = load_published_hashes(published_path)
    if post and post_hash(post) in hashes:
        problems.append("пост уже публиковался (дубль)")

    # Опасные данные в buttons (ссылки)
    for btn in draft.get("buttons") or []:
        label = str(btn.get("label", ""))
        problems += _check_secrets(label)

    risk_level = "low"
    if problems:
        risk_level = "high" if any(
            p.startswith(("найден секрет", "опасная команда", "пост уже публиковался"))
            for p in problems
        ) else "medium"

    status = "approved"
    if problems:
        status = "rejected" if risk_level == "high" else "needs_review"

    return {
        "status": status,
        "risk_level": risk_level,
        "problems": problems[:20],
        "required_changes": required_changes[:10],
        "safe_to_publish": status == "approved",
    }


def save_review(draft_path: Path | str, review: dict) -> Path:
    draft_path = Path(draft_path)
    review_path = draft_path.with_suffix(draft_path.suffix + ".review.json")
    review_path.write_text(
        json.dumps(review, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return review_path


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Использование: python -m src.content_review <draft.json>")
        sys.exit(2)
    draft = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    result = review_draft(draft)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    sys.exit(0 if result["safe_to_publish"] else 1)
