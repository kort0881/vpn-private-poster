#!/usr/bin/env python3
"""Тесты Telegram-форматирования (src/telegram_content.py)."""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import src.telegram_content as tc  # noqa: E402


class TestFormat:
    def test_escape_html(self):
        # quote=False: кавычки не экранируются (Telegram HTML это допускает)
        assert tc._escape("<b>текст</b> & кавычки") == "&lt;b&gt;текст&lt;/b&gt; &amp; кавычки"

    def test_split_short(self):
        parts = tc._split_long("короткий текст")
        assert parts == ["короткий текст"]

    def test_split_long(self):
        long_text = "\n".join(f"строка {i} — текст" for i in range(300))
        parts = tc._split_long(long_text, limit=1000)
        assert len(parts) > 1
        assert all(len(p) <= 1000 for p in parts)
        assert "".join(parts).replace("\n", "") == long_text.replace("\n", "")

    def test_post_hash_stable(self):
        from src.content_review import post_hash
        assert post_hash("x") == post_hash("x")
        assert len(post_hash("x")) == 64


class TestButtons:
    def test_no_manifest(self, tmp_path, monkeypatch):
        monkeypatch.setattr(tc, "CHECKED_DIR", tmp_path)
        assert tc.build_subscription_buttons() == []

    def test_buttons_from_manifest(self, tmp_path, monkeypatch):
        (tmp_path / "Europe_part1_sub.txt").write_text("k1\nk2\n", encoding="utf-8")
        manifest = {
            "files": [
                {"name": "Europe_part1_sub.txt", "region": "Europe", "count": 2},
                {"name": "Asia_part1_sub.txt", "region": "Asia", "count": 1},
            ]
        }
        (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        monkeypatch.setattr(tc, "CHECKED_DIR", tmp_path)
        buttons = tc.build_subscription_buttons()
        assert len(buttons) == 2
        assert buttons[0]["text"].startswith("📥 Europe")
        assert "raw.githubusercontent.com" in buttons[0]["url"]
        assert "Europe_part1_sub.txt" in buttons[0]["url"]

    def test_single_file_download_button(self, tmp_path, monkeypatch):
        (tmp_path / "Other_part1_sub.txt").write_text("k1\n", encoding="utf-8")
        manifest = {"files": [{"name": "Other_part1_sub.txt", "region": "Other", "count": 1}]}
        (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        monkeypatch.setattr(tc, "CHECKED_DIR", tmp_path)
        buttons = tc.build_subscription_buttons()
        assert len(buttons) == 1
        assert buttons[0]["text"] == "📥 Скачать подписку"

    def test_build_post_buttons_optional_urls(self, tmp_path, monkeypatch):
        (tmp_path / "Other_part1_sub.txt").write_text("k1\n", encoding="utf-8")
        manifest = {"files": [{"name": "Other_part1_sub.txt", "region": "Other", "count": 1}]}
        (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        monkeypatch.setattr(tc, "CHECKED_DIR", tmp_path)
        monkeypatch.delenv("TELEGRAM_GUIDE_URL", raising=False)
        monkeypatch.delenv("TELEGRAM_BACKUP_URL", raising=False)
        monkeypatch.delenv("TELEGRAM_STATUS_URL", raising=False)
        monkeypatch.setenv("TELEGRAM_GUIDE_URL", "https://example.com/guide")
        buttons = tc.build_post_buttons()
        assert buttons[0]["text"] == "📥 Скачать подписку"
        assert any(b["text"] == "🛠 Инструкция" for b in buttons)
        assert not any(b["text"] == "🛟 Резервный способ" for b in buttons)
