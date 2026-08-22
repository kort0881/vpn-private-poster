#!/usr/bin/env python3
"""Тесты проверки черновиков (src/content_review.py)."""
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.content_review import review_draft, post_hash  # noqa: E402


def _draft(post="Пост с полезной информацией. Проверено, работает.",
           title="Заголовок", checked_at="2026-08-22T13:00:00+03:00",
           category="update", sources=("own_report",)):
    return {
        "category": category,
        "title": title,
        "post": post,
        "checked_at": checked_at,
        "sources": list(sources),
        "buttons": [],
    }


class TestReview:
    def test_good_draft_approved(self):
        review = review_draft(_draft())
        assert review["status"] == "approved"
        assert review["safe_to_publish"] is True
        assert review["risk_level"] == "low"

    def test_no_title(self):
        review = review_draft(_draft(title=""))
        assert review["status"] == "needs_review"
        assert "нет заголовка" in review["problems"]

    def test_no_date(self):
        review = review_draft(_draft(checked_at=""))
        assert review["status"] == "needs_review"
        assert any("нет даты" in p for p in review["problems"])

    def test_no_sources(self):
        review = review_draft(_draft(sources=()))
        assert any("нет источников" in p for p in review["problems"])

    def test_uuid_rejected(self):
        draft = _draft(post="Ссылка: vless://11111111-2222-3333-4444-555555555555@host")
        review = review_draft(draft)
        assert review["risk_level"] == "high"
        assert review["safe_to_publish"] is False

    def test_bot_token_rejected(self):
        draft = _draft(post="Токен: 123456789:AAHkjasdfghjklqwertyuiopZXCVBNM123456")
        review = review_draft(draft)
        assert review["risk_level"] == "high"

    def test_forbidden_phrase(self):
        draft = _draft(post="Этот VPN гарантированно работает навсегда!")
        review = review_draft(draft)
        assert review["status"] == "needs_review"
        assert any("гарантированно" in p for p in review["problems"])

    def test_too_long(self):
        draft = _draft(post="а" * 5000)
        review = review_draft(draft)
        assert "лимит" in review["problems"][0]

    def test_dangerous_command_rejected(self):
        draft = _draft(post="Выполните: rm -rf /")
        review = review_draft(draft)
        assert review["risk_level"] == "high"

    def test_duplicate_rejected(self, tmp_path):
        post = "Уникальный текст поста для проверки дубля 12345"
        log = tmp_path / "published.jsonl"
        log.write_text(json.dumps({"post_hash": post_hash(post)}) + "\n", encoding="utf-8")
        review = review_draft(_draft(post=post), published_path=log)
        assert review["risk_level"] == "high"
        assert "дубль" in review["problems"][0]

    def test_unverified_number(self):
        report = {"protocol_passed": 19, "total_found": 459}
        draft = _draft(post="Сегодня проверили 99999 конфигураций, прошли 19.")
        review = review_draft(draft, report=report)
        assert review["status"] == "needs_review"
        assert any("99999" in p for p in review["problems"])
