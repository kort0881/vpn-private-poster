#!/usr/bin/env python3
"""PRIVATE POSTER v5 — URL buttons to subscription files, each file = 1 button"""
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
BASE_RAW = 'https://raw.githubusercontent.com/kort0881/vpn-checker-backend/refs/heads/main'

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
    
    # Gather URLs by group, skip black
    urls_by_group = {}
    for cn, us in sorted(cats.items(), key=lambda x: groupprio(getgroup(x[0]))):
        g = getgroup(cn)
        if g == 'X': continue
        if g not in urls_by_group: urls_by_group[g] = []
        for u in us:
            urls_by_group[g].append(u)
    
    # Load keys for counting (dedup across groups)
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
                if k not in seen: seen.add(k); allkeys.append(k); n += 1
            print(f'  {fn}: {len(ks)} total, {n} new')
    
    print(f'\nTotal unique: {len(allkeys)}')
    return allkeys, urls_by_group

def sendphoto(ch, fp, cap='', bot=None):
    if DRY: print(f'[DRY] photo {ch}'); return {'ok': True}
    try:
        with open(fp, 'rb') as ph:
            r = s.post(f'https://api.telegram.org/bot{bot}/sendPhoto',
                data={'chat_id': ch, 'caption': cap, 'parse_mode': 'HTML'}, files={'photo': ph}, timeout=60)
            j = r.json()
            if not j.get('ok'): print(f'photo fail: {j.get("description")}')
            return j
    except Exception as e: print(f'photo error: {e}')
    return {'ok': False}

def sendmsg(ch, text, bot, markup=None):
    if DRY: print(f'[DRY] msg {ch}'); return {'ok': True}
    try:
        p = {'chat_id': ch, 'text': text, 'parse_mode': 'HTML', 'disable_web_page_preview': True}
        if markup: p['reply_markup'] = markup
        r = s.post(f'https://api.telegram.org/bot{bot}/sendMessage', json=p, timeout=30)
        j = r.json()
        if not j.get('ok'): print(f'msg fail: {j.get("description")}')
        return j
    except Exception as e: print(f'msg error: {e}')
    return {'ok': False}

def main():
    if not BOT or not CHAN: print('No TOKEN/CHANNEL'); return 1
    print('PRIVATE POSTER v5\n')
    if DRY: print('DRY RUN\n')
    
    ak, urls_by_group = loadkeys()
    if not ak: print('No keys'); return 1
    total = len(ak)

    # 1. Cover photo with stats
    cap = (f'<b>🔐 VPN Keys</b>\n'
           f'📅 {datetime.now().strftime("%Y-%m-%d %H:%M")}\n'
           f'📦 <b>{total}</b> keys\n\n'
           f'⬇️ Tap buttons below to open subscription files')
    if os.path.exists(COVER):
        r = sendphoto(CHAN, COVER, cap, BOT)
        print(f'Photo: ok={r.get("ok")}')
    else:
        sendmsg(CHAN, cap, BOT)
    time.sleep(1.5)

    # 2. Buttons: each button = 1 subscription file URL
    MX = 100  # max buttons per message
    
    # Sort groups by priority
    group_order = ['EF', 'RF', 'EA', 'RA', 'O']
    for g in group_order:
        urls = urls_by_group.get(g, [])
        if not urls: continue
        
        label_map = {'EF': '🇪🇺 EUROPE (FAST)', 'RF': '🇷🇺 RUSSIA (FAST)', 
                     'EA': '🇪🇺 EUROPE (ALL)', 'RA': '🇷🇺 RUSSIA (ALL)', 'O': 'OTHER'}
        
        for start in range(0, len(urls), MX):
            batch = urls[start:start + MX]
            kbd, row = [], []
            for u in batch:
                fname = u.split('/')[-1].replace('.txt', '')[:30]
                row.append({'text': f'📥 {fname}', 'url': u})
                if len(row) == 2:
                    kbd.append(row); row = []
            if row: kbd.append(row)
            
            title = f'{label_map.get(g, g)}'
            if len(urls) > MX:
                title += f' ({start+1}-{start+len(batch)})'
            
            r = sendmsg(CHAN, f'<b>{title}</b>', BOT, {'inline_keyboard': kbd})
            ok = r.get('ok', False)
            print(f'  {title}: {len(batch)} buttons, ok={ok}')
            if not ok:
                print(f'  ⚠️ FAILED, stopping')
                return 1
            time.sleep(1.0)

    print('\n✅ All subscription buttons sent')
    return 0

if __name__ == '__main__': sys.exit(main())
