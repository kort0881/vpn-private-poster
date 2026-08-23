#!/usr/bin/env python3
"""Тесты единой публикации технического поста (ТЗ3 п.11, src/publish_update.py)."""
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import src.publish_update as pu  # noqa: E402

OLD_TITLE = "Private VPN Subscriptions"

REPORT = {
    "checked_at": "2026-08-23T06:48:00+00:00",
    "total_found": 459,
    "protocol_passed": 21,
    "new_items": 2,
    "removed_items": 1,
    "stable_items": 19,
    "by_region": {"Other": 21},
    "publish_allowed": True,
    "failures": {"protocol": 5},
}
FILE_META = [{"name": "Other_part1_sub.txt", "region": "Other", "count": 21}]


@pytest.fixture
def no_ai(monkeypatch):
    """AI недоступен — всегда fallback."""
    monkeypatch.setattr(pu, "_build_ai_draft", lambda *a, **k: None)


@pytest.fixture
def pub_env(tmp_path, monkeypatch):
    """Окружение публикации: tmp published.jsonl, токены, перехват отправки."""
    monkeypatch.setattr(pu, "PUBLISHED_LOG", tmp_path / "published.jsonl")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:TESTTOKEN")
    monkeypatch.setenv("TELEGRAM_PRIVATE_CHANNEL", "-100test")
    sent = []
    monkeypatch.setattr(
        pu._tg, "publish_post_with_buttons",
        lambda post, buttons=None: sent.append({"post": post, "buttons": buttons}) or True,
    )
    monkeypatch.setattr(pu._tg, "build_post_buttons", lambda: [])
    return {"sent": sent, "log": pu.PUBLISHED_LOG}


class TestNoOldFormat:
    def test_fallback_has_no_old_title(self):
        post = pu.build_fallback_post(REPORT, FILE_META)["post"]
        assert OLD_TITLE not in post
        assert "Обновление подключений" in post

    def test_publish_output_has_no_old_title(self, no_ai, pub_env, capsys):
        pu.publish_update(REPORT, FILE_META)
        out = capsys.readouterr().out
        assert OLD_TITLE not in out
        assert "CONTENT_MODE: enabled" in out
        assert "POST_TYPE: subscription_update" in out
        assert "OLD_POST_FORMAT: disabled" in out


class TestNewPostContent:
    def test_post_contains_numbers_date_warning(self, no_ai, pub_env, capsys):
        pu.publish_update(REPORT, FILE_META)
        out = capsys.readouterr().out
        assert "459" in out          # количество проверенных
        assert "21" in out           # protocol_passed
        assert "23.08.2026" in out   # дата проверки (MSK)
        assert "актуален на момент проверки" in out  # предупреждение

    def test_region_unknown_instead_of_other(self):
        post = pu.build_fallback_post(REPORT, FILE_META)["post"]
        assert "Region unknown" in post
        assert "Other" not in post

    def test_fallback_template_when_ai_absent(self, no_ai, pub_env, capsys):
        stats = pu.publish_update(REPORT, FILE_META)
        out = capsys.readouterr().out
        assert stats["template"] == "fallback"
        assert "POST_TEMPLATE: fallback" in out
        assert "🔐 Обновление подключений" in out


class TestButtons:
    def test_buttons_attached_to_single_post(self, no_ai, pub_env):
        fake_buttons = [{"text": "📥 Скачать подписку", "url": "https://example.com/x"}]
        pub_env["sent"].clear()
        pu._tg.build_post_buttons = lambda: fake_buttons
        stats = pu.publish_update(REPORT, FILE_META)
        assert stats["messages_to_channel"] == 1
        assert len(pub_env["sent"]) == 1
        assert pub_env["sent"][0]["buttons"] == fake_buttons


class TestMskTimeReview:
    """Время MSK — производное от checked_at, должно проходить review."""

    def _draft(self):
        return {
            "category": "update",
            "title": "Обновление подключений",
            "post": "Проверено: 459. Прошли: 21. Проверено: 23.08.2026, 09:48 MSK",
            "checked_at": "2026-08-23T06:48:00+00:00",
            "sources": ["own_report"],
            "buttons": [],
        }

    def test_msk_time_approved_with_checked_at_msk(self):
        report = {**REPORT, "checked_at_msk": "23.08.2026, 09:48 MSK"}
        review = pu._cr.review_draft(self._draft(), report=report)
        assert review["safe_to_publish"] is True

    def test_msk_time_needs_review_without_checked_at_msk(self):
        review = pu._cr.review_draft(self._draft(), report=REPORT)
        assert review["status"] == "needs_review"


class TestOnePostPerRun:
    def test_single_run_sends_one_message(self, no_ai, pub_env):
        stats = pu.publish_update(REPORT, FILE_META)
        assert stats["published"] is True
        assert len(pub_env["sent"]) == 1

    def test_duplicate_hash_not_republished(self, no_ai, pub_env):
        first = pu.publish_update(REPORT, FILE_META)
        assert first["published"] is True
        assert len(pub_env["sent"]) == 1
        second = pu.publish_update(REPORT, FILE_META)
        assert second["skipped"] is True
        assert second["published"] is False
        assert len(pub_env["sent"]) == 1  # второй пост не отправлен

    def test_post_hash_recorded(self, no_ai, pub_env):
        pu.publish_update(REPORT, FILE_META)
        records = [json.loads(line) for line in pub_env["log"].read_text().splitlines() if line.strip()]
        assert len(records) == 1
        assert records[0]["post_hash"] == pu._content_key(REPORT, FILE_META)
