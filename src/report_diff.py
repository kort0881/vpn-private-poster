#!/usr/bin/env python3
"""
Сравнение отчётов проверки конфигураций.

Сравнивает data/current_report.json с data/previous_report.json
по config_hash и определяет:
- новые конфигурации;
- исчезнувшие;
- стабильные;
- изменения по протоколам и регионам;
- изменение средней задержки;
- резкое падение количества рабочих конфигураций.

Никогда не содержит полных конфигураций — только хэши и агрегаты.
"""
from __future__ import annotations

import json
import os
from typing import Any


CRITICAL_DROP_RATIO = 0.5  # падение рабочего пула более чем на 50%


def load_report(path: str) -> dict[str, Any] | None:
    """Загружает JSON-отчёт. Возвращает None, если файла нет или он битый."""
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return None
        return data
    except (ValueError, OSError):
        return None


def _hashes_from_report(report: dict[str, Any] | None) -> set[str]:
    """Множество config_hash из списка items отчёта."""
    if not report:
        return set()
    items = report.get("items", [])
    if not isinstance(items, list):
        return set()
    return {str(i.get("config_hash", "")) for i in items if i.get("config_hash")}


def _avg_latency(report: dict[str, Any] | None) -> float | None:
    """Средняя задержка (сек) по items с latency."""
    if not report:
        return None
    items = report.get("items", [])
    if not isinstance(items, list):
        return None
    latencies = [
        float(i["latency"])
        for i in items
        if isinstance(i.get("latency"), (int, float)) and float(i["latency"]) > 0
    ]
    if not latencies:
        return None
    return round(sum(latencies) / len(latencies), 3)


def _drop_ratio(prev: dict[str, Any] | None, curr: dict[str, Any] | None) -> float | None:
    prev_n = (prev or {}).get("protocol_passed", 0) or 0
    curr_n = (curr or {}).get("protocol_passed", 0) or 0
    if prev_n <= 0:
        return None
    return round((prev_n - curr_n) / prev_n, 3)


def compute_diff(
    prev: dict[str, Any] | None,
    curr: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Сравнивает два отчёта.

    Возвращает словарь:
    {
      "new_items": [...],       # config_hash новых
      "removed_items": [...],   # config_hash исчезнувших
      "stable_items": [...],    # config_hash стабильных
      "new_count": N, "removed_count": N, "stable_count": N,
      "protocol_changes": {...},
      "region_changes": {...},
      "avg_latency_prev": ...,
      "avg_latency_curr": ...,
      "latency_change_ratio": ...,
      "drop_ratio": ...,
      "critical_drop": bool
    }
    """
    prev_hashes = _hashes_from_report(prev)
    curr_hashes = _hashes_from_report(curr)

    new_items = sorted(curr_hashes - prev_hashes)
    removed_items = sorted(prev_hashes - curr_hashes)
    stable_items = sorted(curr_hashes & prev_hashes)

    def _by_key(report: dict[str, Any] | None) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if not report:
            return out
        for i in (report.get("items") or []):
            h = i.get("config_hash")
            if h:
                out[str(h)] = i
        return out

    prev_by_hash = _by_key(prev)
    curr_by_hash = _by_key(curr)

    # Изменения по протоколам и регионам (только стабильные ключи,
    # у которых изменилась характеристика).
    protocol_changes: dict[str, list[str]] = {}
    region_changes: dict[str, list[str]] = {}
    for h in stable_items:
        p, c = prev_by_hash.get(h, {}), curr_by_hash.get(h, {})
        if p.get("protocol") != c.get("protocol"):
            protocol_changes.setdefault(f"{p.get('protocol')}->{c.get('protocol')}", []).append(h)
        if p.get("region") != c.get("region"):
            region_changes.setdefault(f"{p.get('region')}->{c.get('region')}", []).append(h)

    prev_lat, curr_lat = _avg_latency(prev), _avg_latency(curr)
    latency_change_ratio = None
    if prev_lat and curr_lat is not None:
        latency_change_ratio = round((curr_lat - prev_lat) / prev_lat, 3)

    drop_ratio = _drop_ratio(prev, curr)
    critical_drop = bool(drop_ratio is not None and drop_ratio >= CRITICAL_DROP_RATIO)

    return {
        "new_items": new_items,
        "removed_items": removed_items,
        "stable_items": stable_items,
        "new_count": len(new_items),
        "removed_count": len(removed_items),
        "stable_count": len(stable_items),
        "protocol_changes": protocol_changes,
        "region_changes": region_changes,
        "avg_latency_prev": prev_lat,
        "avg_latency_curr": curr_lat,
        "latency_change_ratio": latency_change_ratio,
        "drop_ratio": drop_ratio,
        "critical_drop": critical_drop,
    }


def diff_reports(prev_path: str, curr_path: str) -> dict[str, Any]:
    """Загружает оба файла и возвращает compute_diff(prev, curr)."""
    return compute_diff(load_report(prev_path), load_report(curr_path))


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("Использование: python -m src.report_diff <previous_report.json> <current_report.json>")
        sys.exit(2)
    result = diff_reports(sys.argv[1], sys.argv[2])
    print(json.dumps(result, ensure_ascii=False, indent=2))
