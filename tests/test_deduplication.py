#!/usr/bin/env python3
"""Тесты дедупликации ключей."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import poster_private as pp  # noqa: E402


def test_exact_duplicates_removed():
    keys = [
        "vless://a@h1.com:443",
        "vless://a@h1.com:443",
        "vless://b@h2.com:443",
        "vless://a@h1.com:443",
    ]
    unique, dups = pp.deduplicate(keys)
    assert len(unique) == 2
    assert dups == 2


def test_order_preserved():
    keys = ["vless://a@h1.com:443", "vless://b@h2.com:443", "vless://a@h1.com:443"]
    unique, _ = pp.deduplicate(keys)
    assert unique == ["vless://a@h1.com:443", "vless://b@h2.com:443"]


def test_no_duplicates():
    keys = ["vless://a@h1.com:443", "vless://b@h2.com:443"]
    unique, dups = pp.deduplicate(keys)
    assert len(unique) == 2
    assert dups == 0


def test_different_protocols_not_deduplicated():
    keys = ["ss://x@h1.com:8388", "vless://x@h1.com:443"]
    unique, _ = pp.deduplicate(keys)
    assert len(unique) == 2
