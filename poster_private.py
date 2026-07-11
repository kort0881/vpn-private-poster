#!/usr/bin/env python3
"""VIP key poster - 20 buttons x100, rest buttons x1000 with enhanced filtering"""
import os, sys, requests, re, time
from datetime import datetime
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urlparse, parse_qs

# -------------------- CONFIGURATION --------------------
# Минимальная длина ключа для каждого протокола
MIN_LENGTH = {
    'vless://': 80,
    'vmess://': 150,
    'trojan://': 80,
    'ss://': 50,
    'ssr://': 60,
}

# Обязательные параметры (регулярки) – если их нет, ключ пропускается
REQUIRED_PATTERNS = {
    'vless://': r'\?encryption=',   # у vless должен быть параметр encryption
    'vmess://': r'\?',              # у vmess обычно есть параметры после ?
    'trojan://': r'#',              # у trojan часто есть # после хоста
    'ss://': r'@',                  # ss содержит @
    'ssr://': r':',
}

# Слова с ошибками – если встречаются в строке, ключ отбрасывается
BLACKLIST_WORDS = ['null', 'undefined', 'error', 'invalid', 'false']

# Максимальное число ключей, забираемых из одного файла (защита от спама)
MAX_PER_FILE = 5000

# Общий лимит ключей для публикации (чтобы не перегружать Telegram)
MAX_TOTAL_KEYS = 30000
# -------------------------------------------------------

s = requests.Session()
r = Retry(total=3, backoff_factor=1, status_forcelist=[500,502,503,504], allowed_methods=['HEAD','GET','OPTIONS'])
a = HTTPAdapter(max_retries=r)
s.mount('http://', a); s.mount('https://', a)

DRY = os.environ.get('TELEGRAM_DRY_RUN', '0') == '1'
BOT = os.environ.get('TELEGRAM_BOT_TOKEN')
CHAN = os.environ.get('TELEGRAM_PRIVATE_CHANNEL')
COVER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cover_private.jpg')
SUBURL = 'https://raw.githubusercontent.com/kort0881/vpn-checker-backend/refs/heads/main/checked/subscriptions_list.txt'

def parsecats(t):
    cats, cur = {}, None
    for l in t.strip().split('\n'):
        l = l.strip()
        if not l or l[0] == '#': continue
        m = re.match(r'===\s*(.+?)\s*===', l)
        if m: cur = m.group(1).strip(); cats[cur] = []; continue
        if l.startswith('http') and '.txt' in l and cur: cats[cur].append(l)
    return cats

def getgroup(c):
    c = c.lower()
    if 'black' in c: return 'X'
    if 'europe' in c or 'euro' in c: return 'EF' if ('fast' in c or 'white' in c) else 'EA'
    if 'russia' in c or 'ru_' in c: return 'RF' if ('fast' in c or 'white' in c) else 'RA'
    return 'O'

def groupprio(g): return {'EF':1,'RF':2,'EA':3,'RA':4,'O':5,'X':99}.get(g,99)

def proto_priority(key):
    """Сортировка внутри группы: vless > vmess > trojan > ss > ssr"""
    for p in ['vless://','vmess://','trojan://','ss://','ssr://']:
        if key.startswith(p):
            return ['vless://','vmess://','trojan://','ss://','ssr://'].index(p)
    return 99

def is_valid_key(key):
    """Статическая проверка ключа: длина, обязательные параметры, чёрный список слов"""
    for proto, min_len in MIN_LENGTH.items():
        if key.startswith(proto):
            if len(key) < min_len:
                return False
            # Проверка обязательных параметров
            pattern = REQUIRED_PATTERNS.get(proto)
            if pattern and not re.search(pattern, key):
                return False
            # Чёрный список слов
            for word in BLACKLIST_WORDS:
                if word in key.lower():
                    return False
            return True
    # Если протокол не распознан – пропускаем (можно добавить свою логику)
    return False

def normalize_key(key):
    """Извлекаем основную часть ключа (до ? или #) для дедупликации на уровне сервера"""
    # Убираем параметры и якоря
    for delim in ['?', '#']:
        if delim in key:
            return key.split(delim)[0]
    return key

def fetchkeys(url):
    try:
        r = s.get(url, timeout=30)
        if r.status_code != 200: return []
        res = []
        for l in r.text.strip().split('\n'):
            l = l.strip()
            if not l or l[0] == '#': continue
            # Проверяем, является ли строка ключом
            if any(l.startswith(p) for p in MIN_LENGTH.keys()):
                if is_valid_key(l):
                    res.append(l)
        # Ограничиваем количество ключей из одного файла
        if len(res) > MAX_PER_FILE:
            res = res[:MAX_PER_FILE]
        return res
    except:
        return []

def loadkeys():
    print('Loading subscriptions...')
    try:
        r = s.get(SUBURL, timeout=30)
        if r.status_code != 200: print(f'HTTP {r.status_code}'); return []
    except Exception as e: print(e); return []
    cats = parsecats(r.text)
    print(f'Categories: {len(cats)}')
    for c, u in cats.items(): print(f'  {c}: {len(u)} files')
    
    allkeys, seen = [], set()  # seen хранит нормализованные ключи для глобальной дедупликации
    for cn, us in sorted(cats.items(), key=lambda x: groupprio(getgroup(x[0]))):
        g = getgroup(cn)
        if g == 'X':
            print(f'\nSkip BLACK: {cn}')
            continue
        print(f'\n{cn} -> {g}')
        for u in us:
            ks = fetchkeys(u)
            fn = u.split('/')[-1].split('?')[0]
            n = 0
            for k in ks:
                norm = normalize_key(k)
                if norm not in seen:
                    seen.add(norm)
                    allkeys.append((k, g))  # сохраняем оригинальный ключ для отправки
                    n += 1
            print(f'  {fn}: {len(ks)} total, {n} new after global dedup')
    
    # Сортировка внутри каждой группы по протоколу
    allkeys.sort(key=lambda x: (x[1], proto_priority(x[0])))
    
    # Общий лимит
    if len(allkeys) > MAX_TOTAL_KEYS:
        allkeys = allkeys[:MAX_TOTAL_KEYS]
        print(f'\n⚠️ Trimmed to {MAX_TOTAL_KEYS} keys')
    
    print(f'\nTotal unique: {len(allkeys)}')
    return allkeys

def chunkkeys(keys, sz):
    return [keys[i:i+sz] for i in range(0, len(keys), sz)]

def sendphoto(ch, fp, cap='', bot=None):
    if DRY: print(f'[DRY] photo {ch}'); return True
    try:
        with open(fp, 'rb') as ph:
            r = s.post(f'https://api.telegram.org/bot{bot}/sendPhoto',
                data={'chat_id': ch, 'caption': cap, 'parse_mode': 'HTML'}, files={'photo': ph}, timeout=60)
            j = r.json()
            if not j.get('ok'):
                print(f'photo fail: {j.get("description")}')
                return False
            return True
    except Exception as e:
        print(f'photo error: {e}')
        return False

def sendmsg(ch, text, bot, markup=None):
    if DRY: print(f'[DRY] msg {ch}'); return True
    try:
        p = {'chat_id': ch, 'text': text, 'parse_mode': 'HTML', 'disable_web_page_preview': True}
        if markup: p['reply_markup'] = markup
        r = s.post(f'https://api.telegram.org/bot{bot}/sendMessage', json=p, timeout=30)
        j = r.json()
        if not j.get('ok'):
            print(f'msg fail: {j.get("description")}')
            return False
        return True
    except Exception as e:
        print(f'msg error: {e}')
        return False

def buildkbd(keys, label_prefix):
    kbd, row = [], []
    for i, chunk in enumerate(keys, 1):
        txt = '\n'.join(k for k,_ in chunk)
        row.append({'text': f'{label_prefix} {i}', 'copy_text': {'text': txt}})
        if len(row) == 2: kbd.append(row); row = []
    if row: kbd.append(row)
    return {'inline_keyboard': kbd}

def main():
    if not BOT or not CHAN: print('No TOKEN/CHANNEL'); return 1
    print('PRIVATE POSTER v3 (filtered)\n')
    if DRY: print('DRY RUN\n')
    ak = loadkeys()
    if not ak: print('No keys'); return 1
    total = len(ak)
    small = ak[:2000]  # максимум 20 кнопок x 100
    big = ak[2000:]
    small_chunks = chunkkeys(small, 100)
    big_chunks = chunkkeys(big, 1000)
    print(f'\n{total} keys: {len(small_chunks)} small btns, {len(big_chunks)} big btns')
    cap = f'VPN keys\n{datetime.now().strftime("%Y-%m-%d %H:%M")}\nTotal: {total}'
    if os.path.exists(COVER):
        ok = sendphoto(CHAN, COVER, cap, BOT)
        print(f'Photo sent: {ok}')
    else:
        ok = sendmsg(CHAN, cap, BOT)
        print(f'Cover message sent: {ok}')
    time.sleep(1.5)
    if small_chunks:
        ok = sendmsg(CHAN, f'Small ({len(small_chunks)} x 100)', BOT, buildkbd(small_chunks, 'S'))
        print(f'Small buttons sent: {ok}')
        time.sleep(1.5)
    if big_chunks:
        ok = sendmsg(CHAN, f'\n---\nBig ({len(big_chunks)} x 1000)\n---', BOT, buildkbd(big_chunks, 'B'))
        print(f'Big buttons sent: {ok}')
    print('Done'); return 0

if __name__ == '__main__': sys.exit(main())
