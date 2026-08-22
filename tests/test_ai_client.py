#!/usr/bin/env python3
"""Тесты единого AI-клиента (src/ai_client.py)."""
import json
import os
import sys
from unittest import mock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ai_client import AIClient, AIClientError  # noqa: E402


def _resp(status=200, content="привет"):
    payload = {"choices": [{"message": {"content": content}}]}
    r = mock.Mock()
    r.status_code = status
    r.json.return_value = payload
    return r


class TestClient:
    def setup_method(self):
        os.environ["AI_API_KEY"] = "test-key-123"
        os.environ.pop("AI_BASE_URL", None)
        for k in ("MODEL_PRIMARY", "MODEL_FALLBACK", "MODEL_BLOCK_PRIMARY",
                  "MODEL_BLOCK_FALLBACK", "MODEL_BLOCK_OPTIONAL",
                  "MODEL_SCOUT_PRIMARY", "MODEL_SCOUT_FALLBACK"):
            os.environ.pop(k, None)

    def teardown_method(self):
        os.environ.pop("AI_API_KEY", None)

    def test_default_models(self):
        client = AIClient()
        assert client.model == "openai/gpt-oss-120b"
        assert client.fallback_model == "openai/gpt-oss-20b"

    def test_block_chain_has_three_models(self):
        client = AIClient(chain="block")
        assert client.extra_fallback == "qwen/qwen3.6-27b"

    def test_missing_api_key(self):
        os.environ.pop("AI_API_KEY", None)
        with pytest.raises(AIClientError):
            AIClient()

    def test_generate_ok(self):
        client = AIClient()
        with mock.patch("requests.post", return_value=_resp(200, "ок")):
            text, model = client.generate([{"role": "user", "content": "x"}])
        assert text == "ок"
        assert model == "openai/gpt-oss-120b"

    def test_http_401_raises(self):
        client = AIClient()
        with mock.patch("requests.post", return_value=_resp(401)):
            with pytest.raises(AIClientError) as exc:
                client.generate([{"role": "user", "content": "x"}])
        assert "401" in str(exc.value)

    def test_429_then_ok(self):
        client = AIClient(max_retries=1)
        responses = [_resp(429), _resp(200, "после ретрая")]
        with mock.patch("requests.post", side_effect=responses):
            text, model = client.generate([{"role": "user", "content": "x"}])
        assert text == "после ретрая"

    def test_fallback_used(self):
        client = AIClient()
        # 401 не входит в retry-статусы → primary падает сразу, уходит в fallback
        responses = [_resp(401), _resp(200, "фолбэк")]
        with mock.patch("requests.post", side_effect=responses):
            text, model = client.generate([{"role": "user", "content": "x"}])
        assert text == "фолбэк"
        assert model == "openai/gpt-oss-20b"

    def test_both_fail(self):
        client = AIClient()
        with mock.patch("requests.post", return_value=_resp(500)):
            with pytest.raises(AIClientError):
                client.generate([{"role": "user", "content": "x"}])

    def test_empty_response(self):
        client = AIClient()
        with mock.patch("requests.post", return_value=_resp(200, "   ")):
            with pytest.raises(AIClientError):
                client.generate([{"role": "user", "content": "x"}])

    def test_generate_json_ok(self):
        client = AIClient()
        data = {"category": "update", "title": "T", "post": "P"}
        with mock.patch("requests.post", return_value=_resp(200, json.dumps(data))):
            result, model = client.generate_json([{"role": "user", "content": "x"}])
        assert result["category"] == "update"

    def test_generate_json_fenced(self):
        client = AIClient()
        fenced = "```json\n{\"category\": \"guide\"}\n```"
        with mock.patch("requests.post", return_value=_resp(200, fenced)):
            result, _ = client.generate_json([{"role": "user", "content": "x"}])
        assert result["category"] == "guide"

    def test_generate_json_not_json(self):
        client = AIClient()
        with mock.patch("requests.post", return_value=_resp(200, "просто текст")):
            with pytest.raises(AIClientError):
                client.generate_json([{"role": "user", "content": "x"}])

    def test_no_api_key_in_error(self):
        client = AIClient()
        with mock.patch("requests.post", return_value=_resp(401)):
            try:
                client.generate([{"role": "user", "content": "x"}])
            except AIClientError as exc:
                assert "test-key-123" not in str(exc)
