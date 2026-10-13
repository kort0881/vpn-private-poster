# VPN Private Poster

Автоматический генератор и публикатор VPN-контента.

## Установка

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

## Использование

```bash
python poster_private.py
```

## Структура

- `poster_private.py` — основной скрипт публикации
- `src/` — модули проекта
- `config/` — конфигурации
- `data/` — данные для публикаций
