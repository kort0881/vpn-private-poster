#!/usr/bin/env python3
"""Тесты build_report (poster_private.py) — контракт levels_passed для L4."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from poster_private import build_report  # noqa: E402


def _res(check_level, status, levels_passed, region="Other", protocol="vless"):
    return {
        "config_hash": "a" * 64,
        "check_level": check_level,
        "status": status,
        "region": region,
        "protocol": protocol,
        "latency": 0.1,
        "error_code": None,
        "levels_passed": levels_passed,
    }


SETTINGS = {"min_publish_count": 1}


class TestProtocolPassedCounting:
    def test_l4_success_with_levels_passed_counts(self):
        """Успешный L4 (check_level=protocol + 'protocol' в levels_passed) считается."""
        results = [_res("protocol", "working", ["parse", "dns", "tcp", "protocol"])]
        report = build_report(results, total_found=100, parsed=50, duration=1.0,
                              publish_allowed=True, published_count=1, settings=SETTINGS)
        assert report["protocol_passed"] == 1
        assert len(report["items"]) == 1

    def test_l4_success_without_protocol_level_counts_zero(self):
        """Контракт: если в levels_passed нет 'protocol' — НЕ считается (баг v32)."""
        results = [_res("protocol", "working", ["parse", "dns", "tcp"])]
        report = build_report(results, total_found=100, parsed=50, duration=1.0,
                              publish_allowed=True, published_count=1, settings=SETTINGS)
        assert report["protocol_passed"] == 0
        assert report["items"] == []
