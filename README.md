# Private VPN Keys Telegram Poster

Автоматическая публикация VPN-ключей в **приватный Telegram-канал** каждые 2 часа.

## Возможности

- Загружает ключи из `results/premium/` (elite.txt, premium.txt, good.txt)
- Автоматический fallback на `verified_*.txt`, `semi_dead_*.txt`, `checked/latest/verified.txt`
- Отправляет файл со всеми ключами + обложка `cover_private.jpg`
- Кнопки со ссылками на подписки (из GitHub API)
- Кнопки с активными прокси для Telegram (из telegram-proxy-collector)
- Запуск каждые 2 часа + ручной запуск
- Работает бесплатно на GitHub Actions

## Структура репозитория

```
/
├── poster_private.py          # основной скрипт
├── requirements.txt           # зависимости
├── cover_private.jpg          # обложка (добавить свою)
├── results/
│   └── premium/               # сюда положить elite.txt, premium.txt, good.txt
├── checked/
│   └── latest/
│       └── verified.txt       # fallback (опционально)
└── .github/workflows/
    └── schedule.yml           # GitHub Actions
```

## Настройка

### 1. Fork или клонирование

Склонируйте репозиторий и добавьте свои файлы.

### 2. Файлы с ключами

Положите файлы в `results/premium/`:
- `elite.txt`
- `premium.txt`
- `good.txt`

Или в `results/`:
- `verified_*.txt`
- `semi_dead_*.txt`

### 3. Обложка

Добавьте `cover_private.jpg` в корень. Если её нет — скрипт отправит только файл без фото.

### 4. Секреты (Secrets)

Перейдите в **Settings → Secrets and variables → Actions** и добавьте:

| Secret | Описание |
|--------|----------|
| `TELEGRAM_BOT_TOKEN` | Токен бота (получить у @BotFather) |
| `TELEGRAM_PRIVATE_CHANNEL` | ID канала (например `-1001234567890`) |
| `TELEGRAM_DRY_RUN` | `1` для тестового режима (опционально) |

### 5. Запуск

- **Автоматически**: каждые 2 часа (0:00, 2:00, 4:00... UTC)
- **Вручную**: перейдите в **Actions → Private Poster → Run workflow**

## Проверка логов

После запуска откройте **Actions → нужный workflow → job** — увидите логи с эмодзи.

## DRY_RUN режим

Установите `TELEGRAM_DRY_RUN=1` — скрипт выполнится, но ничего не отправит.
