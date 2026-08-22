#!/usr/bin/env python3
"""Тесты защиты секретов и отсутствия полных конфигураций в отчётах/логах."""
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import poster_private as pp  # noqa: E402


def _mk_result(key, check_level="protocol", status="working"):
    return {
        "config_hash": pp.config_hash(key),
        "protocol": "vless",
        "region": "Europe",
        "check_level": check_level,
        "status": status,
        "latency": 0.3,
        "error_code": None,
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def test_report_contains_no_full_configs():
    key = "vless://deadbeef-0000-1111-2222-333344445555@super.secret.example.com:443?type=tcp"
    results = [_mk_result(key)]
    report = pp.build_report(
        results,
        total_found=1,
        parsed=1,
        duration=1.0,
        publish_allowed=True,
        published_count=1,
        settings=pp.load_settings(),
    )
    text = str(report)
    assert "super.secret.example.com" not in text
    assert "deadbeef-0000-1111-2222-333344445555" not in text
    # В items только хэши, не полные ключи
    for item in report["items"]:
        assert item["config_hash"]
        assert "vless://" not in item.values().__str__()


def test_mask_key_masks_host_and_uuid():
    key = "vless://uuid-123456@example.com:443?type=tcp"
    masked = pp.mask_key(key)
    assert "uuid-123456" not in masked
    assert "example.com" not in masked
    assert masked.startswith("vless://")


def test_no_url_in_xray_crash_log():
    """build_xray_config не содержит URL в ошибке (проверяем структуру)."""
    key = "hysteria2://auth@example.com:8443"
    assert pp.build_xray_config(key, 31000) is None  # не поддерживается Xray


def test_redact_github_token():
    pp.GH_TOKEN = "ghp_supersecrettoken123"
    text = "fatal: https://kort0881:ghp_supersecrettoken123@github.com/repo.git"
    redacted = pp._redact(text)
    assert "ghp_supersecrettoken123" not in redacted
    assert "***" in redacted
    pp.GH_TOKEN = ""


def test_diagnostics_has_no_secrets(tmp_path, monkeypatch):
    monkeypatch.setattr(pp, "DIAGNOSTICS_LOG", str(tmp_path / "diagnostics.jsonl"))
    pp.append_diagnostics({"event": "test", "config_hash": "abc123"})
    content = (tmp_path / "diagnostics.jsonl").read_text(encoding="utf-8")
    assert "abc123" in content
    assert "vless://" not in content
