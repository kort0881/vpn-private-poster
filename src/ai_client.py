#!/usr/bin/env python3
"""
Единый AI-клиент для всех скриптов проекта.

- OpenAI Chat Completions API (Groq-совместимый), сторонние агрегаторы не используются.
- Адрес API: AI_BASE_URL (по умолчанию https://api.groq.com/openai/v1).
- Ключ: AI_API_KEY. Значение ключа никогда не печатается и не сохраняется.
- Цепочки fallback (по ТЗ):
    обычный контент:  openai/gpt-oss-120b → openai/gpt-oss-20b
    block_ai_poster:  openai/gpt-oss-120b → groq/compound → qwen/qwen3.6-27b
    scout_radar:      openai/gpt-oss-120b → openai/gpt-oss-20b
"""
from __future__ import annotations

import json
import os
import time
from typing import Any, Sequence

import requests


class AIClientError(RuntimeError):
    """Понятная ошибка AI-клиента без секретов в тексте."""


MODEL_CHAINS = {
    "content": ("openai/gpt-oss-120b", "openai/gpt-oss-20b"),
    "block": ("openai/gpt-oss-120b", "groq/compound", "qwen/qwen3.6-27b"),
    "scout": ("openai/gpt-oss-120b", "openai/gpt-oss-20b"),
}

ENV_MODEL_KEYS = {
    "content": ("MODEL_PRIMARY", "MODEL_FALLBACK"),
    "block": ("MODEL_BLOCK_PRIMARY", "MODEL_BLOCK_FALLBACK", "MODEL_BLOCK_OPTIONAL"),
    "scout": ("MODEL_SCOUT_PRIMARY", "MODEL_SCOUT_FALLBACK"),
}

# HTTP-статусы, при которых пробуем retry
RETRY_STATUSES = (408, 429, 500, 502, 503, 504)


class AIClient:
    def __init__(
        self,
        chain: str = "content",
        model: str | None = None,
        fallback_model: str | None = None,
        timeout: int = 90,
        max_retries: int = 2,
    ) -> None:
        self.api_key = os.getenv("AI_API_KEY", "").strip()
        if not self.api_key:
            raise AIClientError(
                "Не задана переменная окружения AI_API_KEY. "
                "Добавьте её в секреты GitHub Actions или в .env."
            )

        self.base_url = os.getenv(
            "AI_BASE_URL", "https://api.groq.com/openai/v1"
        ).rstrip("/")

        env_keys = ENV_MODEL_KEYS.get(chain, ENV_MODEL_KEYS["content"])
        env_models = [os.getenv(k, "").strip() for k in env_keys]
        default_chain = MODEL_CHAINS.get(chain, MODEL_CHAINS["content"])

        self.model = model or env_models[0] or default_chain[0]
        self.fallback_model = fallback_model or env_models[1] or default_chain[1]
        self.extra_fallback = env_models[2] if len(env_models) > 2 else None
        if not self.extra_fallback and len(default_chain) > 2:
            self.extra_fallback = default_chain[2]

        self.timeout = timeout
        self.max_retries = max_retries

    def _request(self, model: str, messages: Sequence[dict]) -> str:
        url = f"{self.base_url}/chat/completions"
        payload: dict[str, Any] = {
            "model": model,
            "messages": list(messages),
            "temperature": 0.4,
            "max_tokens": 1800,
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        last_error: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                response = requests.post(
                    url, json=payload, headers=headers, timeout=self.timeout
                )
            except requests.exceptions.RequestException as exc:
                last_error = exc
                if attempt < self.max_retries:
                    time.sleep(2 * (attempt + 1))
                    continue
                break

            if response.status_code in RETRY_STATUSES and attempt < self.max_retries:
                last_error = AIClientError(f"AI API вернул HTTP {response.status_code}")
                time.sleep(2 * (attempt + 1))
                continue

            if response.status_code >= 400:
                raise AIClientError(f"AI API вернул HTTP {response.status_code}")

            try:
                data = response.json()
                content = data["choices"][0]["message"]["content"]
            except (ValueError, KeyError, IndexError, TypeError) as exc:
                raise AIClientError("AI API вернул неожиданный формат ответа") from exc

            if not isinstance(content, str) or not content.strip():
                raise AIClientError("AI вернул пустой ответ")
            return content.strip()

        raise AIClientError(f"AI API недоступен: {last_error}")

    def _models(self) -> list[str]:
        models = [self.model, self.fallback_model]
        if self.extra_fallback:
            models.append(self.extra_fallback)
        return models

    def generate(
        self,
        messages: Sequence[dict],
        use_fallback: bool = True,
    ) -> tuple[str, str]:
        """
        Вызывает AI с переключением по цепочке моделей.

        Возвращает (текст, фактически использованная модель).
        """
        errors: list[str] = []
        for idx, model in enumerate(self._models()):
            try:
                result = self._request(model, messages)
                return result, model
            except AIClientError as exc:
                errors.append(str(exc))
                if not use_fallback:
                    raise
                if idx < len(self._models()) - 1:
                    time.sleep(2)
        raise AIClientError(
            "Недоступны основная и резервная AI-модели: " + "; ".join(errors)
        )

    def generate_json(
        self,
        messages: Sequence[dict],
        use_fallback: bool = True,
    ) -> tuple[dict, str]:
        """Генерирует ответ и парсит JSON. Возвращает (dict, модель)."""
        text, model = self.generate(messages, use_fallback=use_fallback)
        try:
            return json.loads(text), model
        except ValueError as exc:
            # Пробуем вырезать JSON-блок из текста (```json ... ```)
            start = text.find("{")
            end = text.rfind("}")
            if start != -1 and end > start:
                try:
                    return json.loads(text[start:end + 1]), model
                except ValueError:
                    pass
            raise AIClientError(
                "AI вернул не-JSON ответ (ожидался JSON по формату ТЗ)"
            ) from exc


if __name__ == "__main__":
    import sys

    chain = sys.argv[1] if len(sys.argv) > 1 else "content"
    client = AIClient(chain=chain)
    text, model = client.generate(
        [{"role": "user", "content": "Ответь одним словом: работает?"}]
    )
    print(f"модель: {model}")
    print(text[:200])
