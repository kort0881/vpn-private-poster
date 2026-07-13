name: Update Private VPN Keys

on:
  schedule:
    - cron: '0 */6 * * *'  # каждые 6 часов
  workflow_dispatch:       # ручной запуск

jobs:
  update:
    runs-on: ubuntu-latest
    timeout-minutes: 15    # максимум 15 минут (вместо 6 часов!)
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
        with:
          fetch-depth: 0
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      
      - name: Install dependencies
        run: |
          pip install requests urllib3
      
      - name: Run private poster
        env:
          TELEGRAM_BOT_TOKEN: ${{ secrets.TELEGRAM_BOT_TOKEN }}
          TELEGRAM_PRIVATE_CHANNEL: ${{ secrets.TELEGRAM_PRIVATE_CHANNEL }}
          GH_TOKEN: ${{ secrets.GH_TOKEN }}
          TELEGRAM_DRY_RUN: "0"
        run: |
          python3 private_poster.py
