#!/usr/bin/env python3
"""Тесты сравнения отчётов (src/report_diff.py)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.report_diff import compute_diff, load_report  # noqa: E402


def _item(h, protocol="vless", region="Europe", latency=0.5):
    return {
        "config_hash": h,
        "protocol": protocol,
        "region": region,
        "check_level": "protocol",
        "status": "working",
        "latency": latency,
    }


def test_new_removed_stable():
    prev = {"protocol_passed": 3, "items": [
        _item("a"), _item("b"), _item("c"),
    ]}
    curr = {"protocol_passed": 3, "items": [
        _item("a"), _item("b"), _item("d"),
    ]}
    diff = compute_diff(prev, curr)
    assert diff["new_items"] == ["d"]
    assert diff["removed_items"] == ["c"]
    assert sorted(diff["stable_items"]) == ["a", "b"]
    assert diff["new_count"] == 1
    assert diff["removed_count"] == 1
    assert diff["stable_count"] == 2


def test_no_previous_report():
    diff = compute_diff(None, {"protocol_passed": 2, "items": [_item("a"), _item("b")]})
    assert diff["new_count"] == 2
    assert diff["removed_count"] == 0
    assert diff["critical_drop"] is False


def test_critical_drop_detected():
    prev = {"protocol_passed": 10, "items": [_item(f"k{i}") for i in range(10)]}
    curr = {"protocol_passed": 2, "items": [_item("k1"), _item("k2")]}
    diff = compute_diff(prev, curr)
    assert diff["drop_ratio"] == 0.8
    assert diff["critical_drop"] is True


def test_no_drop():
    prev = {"protocol_passed": 5, "items": [_item("a"), _item("b"), _item("c"), _item("d"), _item("e")]}
    curr = {"protocol_passed": 4, "items": [_item("a"), _item("b"), _item("c"), _item("d")]}
    diff = compute_diff(prev, curr)
    assert diff["drop_ratio"] == 0.2
    assert diff["critical_drop"] is False


def test_latency_change():
    prev = {"protocol_passed": 1, "items": [_item("a", latency=0.2)]}
    curr = {"protocol_passed": 1, "items": [_item("a", latency=0.4)]}
    diff = compute_diff(prev, curr)
    assert diff["avg_latency_prev"] == 0.2
    assert diff["avg_latency_curr"] == 0.4
    assert diff["latency_change_ratio"] == 1.0


def test_protocol_and_region_changes():
    prev = {"protocol_passed": 1, "items": [_item("a", protocol="vless", region="Europe")]}
    curr = {"protocol_passed": 1, "items": [_item("a", protocol="trojan", region="Asia")]}
    diff = compute_diff(prev, curr)
    assert diff["protocol_changes"].get("vless->trojan") == ["a"]
    assert diff["region_changes"].get("Europe->Asia") == ["a"]


def test_load_report_missing_file():
    assert load_report("/nonexistent/path.json") is None
