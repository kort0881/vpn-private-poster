#!/usr/bin/env python3
"""Тесты парсинга и очистки ключей (P1: исправление парсинга)."""
import base64
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import poster_private as pp  # noqa: E402


class TestProtocolPreservation:
    """Схема протокола никогда не меняется."""

    def test_ss_not_converted_to_vless(self):
        # Критический баг v31: ss:// → vless:// заменой префикса
        key = "ss://YWVzLTI1Ni1nY206cGFzcw==@example.com:8388"
        cleaned = pp.clean_key(key)
        assert cleaned == key
        assert cleaned.startswith("ss://")
        assert not cleaned.startswith("vless://")

    def test_vmess_stays_vmess(self):
        key = "vmess://uuid@example.com:443?type=ws&path=/"
        cleaned = pp.clean_key(key)
        assert cleaned.startswith("vmess://")

    def test_trojan_stays_trojan(self):
        key = "trojan://password@example.com:443?sni=example.com"
        cleaned = pp.clean_key(key)
        assert cleaned.startswith("trojan://")

    def test_vless_stays_vless(self):
        key = "vless://uuid@example.com:443?type=tcp"
        cleaned = pp.clean_key(key)
        assert cleaned.startswith("vless://")

    def test_hysteria2_stays_hysteria2(self):
        key = "hysteria2://auth@example.com:8443?sni=example.com"
        cleaned = pp.clean_key(key)
        assert cleaned.startswith("hysteria2://")

    def test_hy2_stays_hy2(self):
        key = "hy2://auth@example.com:8443"
        cleaned = pp.clean_key(key)
        assert cleaned.startswith("hy2://")


class TestSupportedProtocols:
    def test_all_supported(self):
        for proto in ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://"):
            assert pp.is_supported_protocol(proto + "x"), proto

    def test_ssr_unsupported(self):
        assert not pp.is_supported_protocol("ssr://abc:123@1.2.3.4")

    def test_garbage_unsupported(self):
        assert not pp.is_supported_protocol("hello world")
        assert not pp.is_supported_protocol("http://example.com")


class TestCleanKey:
    def test_strips_whitespace(self):
        assert pp.clean_key("  vless://x@h.com:443  ") == "vless://x@h.com:443"

    def test_strips_comment_after_space(self):
        assert pp.clean_key("vless://x@h.com:443 # free vpn") == "vless://x@h.com:443"

    def test_html_entities_decoded(self):
        key = pp.clean_key("trojan://p@h.com:443?x=1&amp;y=2")
        assert "&" in key and "&amp;" not in key

    def test_empty_returns_none(self):
        assert pp.clean_key("   ") is None
        assert pp.clean_key("") is None
        assert pp.clean_key(None) is None

    def test_short_garbage_returns_none(self):
        assert pp.clean_key("abc") is None


class TestParseKey:
    def test_vless_query_preserved(self):
        key = (
            "vless://uuid@example.com:443"
            "?type=tcp&security=reality&sni=ya.ru&pbk=KEY&sid=abc"
            "&fp=chrome&flow=xtls-rprx-vision&spx=/spx"
        )
        p = pp.parse_key(key)
        assert p is not None
        assert p["host"] == "example.com"
        assert p["port"] == 443
        assert p["query"]["sni"] == ["ya.ru"]
        assert p["query"]["pbk"] == ["KEY"]
        assert p["query"]["sid"] == ["abc"]
        assert p["query"]["fp"] == ["chrome"]
        assert p["query"]["flow"] == ["xtls-rprx-vision"]
        assert p["query"]["spx"] == ["/spx"]

    def test_vmess_base64_payload(self):
        data = {
            "v": 2, "ps": "name", "add": "5.6.7.8", "port": 443,
            "id": "id123", "aid": 0, "net": "ws", "type": "none",
            "host": "h.ru", "path": "/ws", "tls": "tls", "sni": "h.ru",
        }
        b64 = base64.b64encode(json.dumps(data).encode()).decode()
        b64 = b64.replace("/", "_").replace("+", "-")
        p = pp.parse_key("vmess://" + b64)
        assert p is not None
        assert p["host"] == "5.6.7.8"
        assert p["port"] == 443
        assert p["query"]["id"] == ["id123"]
        assert p["query"]["net"] == ["ws"]

    def test_vmess_plain_url(self):
        p = pp.parse_key("vmess://uuid@8.8.8.8:8443?type=ws&path=/x")
        assert p is not None
        assert p["host"] == "8.8.8.8"
        assert p["port"] == 8443

    def test_trojan_parse(self):
        p = pp.parse_key("trojan://pass@example.com:443?sni=example.com&type=ws&path=/p")
        assert p is not None
        assert p["protocol"] == "trojan"
        assert p["username"] == "pass"
        assert p["query"]["sni"] == ["example.com"]

    def test_ss_parse_base64_userinfo(self):
        p = pp.parse_key("ss://YWVzLTI1Ni1nY206cGFzcw==@example.com:8388")
        assert p is not None
        assert p["host"] == "example.com"
        assert p["port"] == 8388
        method, password = pp._parse_ss(
            "ss://YWVzLTI1Ni1nY206cGFzcw==@example.com:8388", p
        )
        assert method == "aes-256-gcm"
        assert password == "pass"

    def test_hysteria2_parse(self):
        p = pp.parse_key("hysteria2://auth@example.com:8443?sni=example.com&insecure=1")
        assert p is not None
        assert p["protocol"] == "hysteria2"
        assert p["username"] == "auth"

    def test_ss_wrapped_vless_detected(self):
        # ss:// обёртка настоящего VLESS (reality) — префикс НЕ меняется,
        # но протокол определяется по содержимому
        key = (
            "ss://00a8f2d4-d565-4d8d-89b3-123456789abc@example.com:443"
            "?type=grpc&encryption=none&serviceName=%40VPNCUSTOMIZE"
            "&sni=www.example.com&fp=random&security=reality&pbk=KEY&sid=4c226372"
        )
        p = pp.parse_key(key)
        assert p is not None
        assert p["username"] == "00a8f2d4-d565-4d8d-89b3-123456789abc"
        assert pp.detect_wrapped_vless(p["query"]) is True
        method, password = pp._parse_ss(key, p)
        assert method is None  # это НЕ настоящий shadowsocks
        # Проверка идёт как vless, префикс не заменяется
        cfg = pp.build_xray_config(key, 31000)
        assert cfg is not None
        assert cfg["outbounds"][0]["protocol"] == "vless"
        assert cfg["outbounds"][0]["streamSettings"]["security"] == "reality"

    def test_ss_plain_not_wrapped(self):
        key = "ss://chacha20-ietf-poly1305:password@example.com:8388"
        p = pp.parse_key(key)
        assert pp.detect_wrapped_vless(p["query"]) is False
        cfg = pp.build_xray_config(key, 31001)
        assert cfg is not None
        assert cfg["outbounds"][0]["protocol"] == "shadowsocks"

    def test_garbage_parse_none(self):
        assert pp.parse_key("not a url") is None
        assert pp.parse_key("") is None


class TestMasking:
    def test_mask_key_hides_host_tail(self):
        key = "vless://uuid@super.secret.host.com:443?type=tcp"
        masked = pp.mask_key(key)
        assert "super.secret.host.com" not in masked
        assert masked.startswith("vless://")
        assert "***" in masked

    def test_mask_key_no_uuid(self):
        key = "vless://deadbeef-1234@example.com:443"
        masked = pp.mask_key(key)
        assert "deadbeef-1234" not in masked

    def test_config_hash_stable(self):
        key = "vless://uuid@example.com:443?type=tcp"
        assert pp.config_hash(key) == pp.config_hash(key)
        assert len(pp.config_hash(key)) == 64
