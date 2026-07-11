#!/usr/bin/env python3
"""VIP key poster - 20 buttons x100, rest buttons x1000"""
import os, sys, requests, re, time
from datetime import datetime
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

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

def fetchkeys(url):
    try:
        r = s.get(url, timeout=30)
        if r.status_code != 200: return []
        res = []
        for l in r.text.strip().split('\n'):
            l = l.strip()
            if not l or l[0] == '#': continue
            if any(l.startswith(p) for p in ['vless://','vmess://','trojan://','ss://','ssr://']): res.append(l)
        return res
    except: return []

def loadkeys():
    print('Loading subscriptions...')
    try:
        r = s.get(SUBURL, timeout=30)
        if r.status_code != 200: print(f'HTTP {r.status_code}'); return []
    except Exception as e: print(e); return []
    cats = parsecats(r.text)
    print(f'Categories: {len(cats)}')
    for c, u in cats.items(): print(f'  {c}: {len(u)} files')
    allkeys, seen = [], set()
    for cn, us in sorted(cats.items(), key=lambda x: groupprio(getgroup(x[0]))):
        g = getgroup(cn)
        if g == 'X': print(f'\nSkip BLACK: {cn}'); continue
        print(f'\n{cn} -> {g}')
        for u in us:
            ks = fetchkeys(u)
            fn = u.split('/')[-1].split('?')[0]
            n = 0
            for k in ks:
                if k not in seen: seen.add(k); allkeys.append((k,g)); n += 1
            print(f'  {fn}: {len(ks)} total, {n} new')
    print(f'\nTotal: {len(allkeys)}')
    return allkeys

def chunkkeys(keys, sz): return [keys[i:i+sz] for i in range(0, len(keys), sz)]

def sendphoto(ch, fp, cap='', bot=None):
    if DRY: print(f'[DRY] photo {ch}'); return
    try:
        with open(fp, 'rb') as ph:
            s.post(f'https://api.telegram.org/bot{bot}/sendPhoto',
                data={'chat_id': ch, 'caption': cap, 'parse_mode': 'HTML'}, files={'photo': ph}, timeout=60)
    except: pass

def sendmsg(ch, text, bot, markup=None):
    if DRY: print(f'[DRY] msg {ch}'); return
    try:
        p = {'chat_id': ch, 'text': text, 'parse_mode': 'HTML', 'disable_web_page_preview': True}
        if markup: p['reply_markup'] = markup
        s.post(f'https://api.telegram.org/bot{bot}/sendMessage', json=p, timeout=30)
    except: pass

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
    print('PRIVATE POSTER v3\n')
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
    if os.path.exists(COVER): sendphoto(CHAN, COVER, cap, BOT)
    else: sendmsg(CHAN, cap, BOT)
    time.sleep(1)
    if small_chunks:
        sendmsg(CHAN, f'Small ({len(small_chunks)} x 100)', BOT, buildkbd(small_chunks, 'S'))
        time.sleep(0.5)
    if big_chunks:
        sendmsg(CHAN, f'\n---\nBig ({len(big_chunks)} x 1000)\n---', BOT, buildkbd(big_chunks, 'B'))
    print('Done'); return 0

if __name__ == '__main__': sys.exit(main())
