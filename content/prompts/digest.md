# Рубрика: DIGEST — ежедневный дайджест

Публикуй максимум один раз в день. Если существенных изменений нет —
НЕ публикуй (digest только при new_items>0, removed_items>0 или
critical_drop в отчёте).

## Данные (из current_report.json)
- total_found, protocol_passed, new_items, removed_items, stable_items;
- checked_at (переведи в MSK).

## Шаблон

📊 Итоги дня

Сегодня:

• проверено: {total_found};
• полную проверку прошли: {protocol_passed};
• добавлено: {new_items};
• удалено: {removed_items};
• стабильных вариантов: {stable_items}.

Что изменилось:

✅ {change_1}
⚠️ {change_2}
🛠 {change_3}

Рекомендация:
{one_practical_recommendation}

Подробные подключения опубликованы отдельным сообщением.

🕒 Данные актуальны на: {checked_at}
