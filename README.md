# Private VPN Keys Telegram Poster

Автоматическая публикация VPN-ключей в **приватный Telegram-канал** каждые 2 часа.

## Что делает

1. **Загружает** сырые ключи из `all_new.txt`
2. **Очищает** от мусора, удаляет дубликаты
3. **Заменяет** все домены на единый адрес `dostyp_k_internety`
4. **Проверяет** каждый ключ TCP-соединением (таймаут 5 сек)
5. **Группирует** по регионам: Europe, Asia, USA, Russia, Other
6. **Сортирует** по задержке внутри групп
7. **Разбивает** на файлы по 100 ключей каждый
8. **Пушит** файлы в `checked/` репозитория
9. **Отправляет** в Telegram обложку + кнопки-ссылки на каждый файл

## Структура

```
/
├── poster_private.py          # основной скрипт
├── requirements.txt           # зависимости
├── cover_private.jpg          # обложка (добавить свою)
├── checked/                   # сюда помещаются готовые файлы (через git push)
└── .github/workflows/
    └── schedule.yml           # GitHub Actions (каждые 2 часа)
```

## Настройка

### Secrets (Settings → Secrets and variables → Actions)

| Secret | Описание |
|--------|----------|
| `TELEGRAM_BOT_TOKEN` | Токен бота (получить у @BotFather) |
| `TELEGRAM_PRIVATE_CHANNEL` | ID канала (например `-1001234567890`) |
| `TELEGRAM_DRY_RUN` | `1` для тестового режима (опционально) |
| `GH_TOKEN` | GitHub Personal Access Token с правами push |

### Источник ключей

Сейчас используется:
`https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/refs/heads/main/data/githubmirror/new/all_new.txt`

Изменить в `poster_private.py` → переменная `SOURCE_URL`.

## Запуск

- **Автоматически**: каждые 2 часа (cron: `0 */2 * * *`)
- **Вручную**: перейдите в **Actions → Private Poster → Run workflow**

## DRY_RUN режим

Установите `TELEGRAM_DRY_RUN=1` — скрипт выполнится, но ничего не отправит и не запушит.
