# LOCAL TESTING — vpn-private-poster

Дата: 2026-08-22
Окружение: WSL (Ubuntu, python 3.14, venv .venv с pytest)

## Команды

```bash
# Установка зависимостей (первый раз)
python3 -m venv --system-site-packages .venv
./.venv/bin/pip install pytest

# Тесты
./.venv/bin/python -m pytest tests/ -q
# Результат: 42 passed

# Компиляция
python3 -m compileall .

# Dry-run poster (без push и Telegram)
env -u HTTPS_PROXY -u ALL_PROXY -u HTTP_PROXY \
  TELEGRAM_DRY_RUN=1 ./.venv/bin/python poster_private.py
```

Примечание: из WSL для доступа к GitHub (raw.githubusercontent.com)
нужно убирать socks-прокси из окружения (`-u HTTPS_PROXY -u ALL_PROXY -u HTTP_PROXY`).

## Результат dry-run (полный запуск, 1000 ключей)

- Загружено 37 525 строк из 3 источников, после очистки/дедупа: 1000 ключей.
- Протоколы в первой тысяче: ss (включая ss-обёртки VLESS) — 869, hysteria2/hy2 — 131.
- L2 DNS прошли: 797. L3 TCP прошли: 207.
- L4 protocol (Xray 25.12.8): проверено 207 ключей, **protocol_passed: 7**.
- Hysteria2: 8 ключей с check_level=tcp_only (UDP/QUIC — Xray не проверяет), НЕ публикуются как verified.
- Создан `Other_part1_sub.txt` (7 ключей) + `checked/manifest.json`, атомарная замена.
- Отчёты записаны: `data/current_report.json`, `data/diagnostics.jsonl`.
- Push и Telegram в dry-run пропущены. Exit code 0.

## Успешные проверки

1. ss:// НЕ превращается в vless:// (тест test_ss_not_converted_to_vless).
2. Публикуются только protocol_passed ключи (TCP-fallback запрещён).
3. ss-обёртки настоящего VLESS (reality/tls + pbk/sid/UUID) определяются
   по содержимому и проверяются как vless — префикс в подписках НЕ меняется.
4. Настоящий shadowsocks проверяется как shadowsocks (валидные cipher из
   белого списка).
5. Hysteria2 не отправляется в Xray — остаётся tcp_only, в verified не попадает.
6. Xray 25.12.8: конфиги для vless/vmess/trojan/ss собираются корректно,
   свободные порты (get_free_port), уникальные tmp-диры, лимит 3 параллельных
   процесса, безопасные сообщения об ошибках (без URL ключей).
7. Отчёты не содержат полных конфигураций — только sha256 (config_hash),
   протокол, регион, задержку, статус.
8. Атомарная замена checked/ с manifest.json; при пустом/малом результате
   предыдущий набор сохраняется.
9. Xray 26.x НЕ используется: в 26.7.11 удалён allowInsecure из TLS-конфига
   (известная грабля) — используется 25.12.8 (как в проде владельца).

## Неуспешные / невозможные проверки

- Полная UDP/QUIC-проверка Hysteria2 невозможна локально и в GitHub Actions
  (нужен sing-box/hysteria-клиент) — зафиксировано ограничением.
- VMess/Trojan отсутствовали в первой тысяче ключей — их Xray-ветки покрыты
  модульными тестами (build_xray_config), но не живым прогоном.
- Push в GitHub и отправка в Telegram в dry-run не выполнялись (намеренно).

## Нужные GitHub Secrets

Обязательные: TELEGRAM_BOT_TOKEN, TELEGRAM_PRIVATE_CHANNEL, GH_TOKEN
(VPNPRIVATEPOSTER). Для AI-контура (P3): AI_API_KEY, TELEGRAM_ADMIN_CHAT_ID.

## Ручной запуск workflow

В репозитории: Actions → Private Poster → Run workflow (workflow_dispatch).
