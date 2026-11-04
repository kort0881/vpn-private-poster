#!/usr/bin/env python3
"""debug_xray.py — гоняет 5 ключей через Xray с полным stderr."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import requests
from poster_private import (  # ← ИСПРАВЛЕНО: poster_private, не advanced_checker
    build_xray_config,
    get_free_port,
    XRAY_BIN,
)

SRC = "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/refs/heads/main/data/githubmirror/clean/vless.txt"


def validate_config(cfg: dict) -> tuple[bool, str]:
    if not cfg or not cfg.get("outbounds"):
        return False, "no_outbound"
    out = cfg["outbounds"][0]
    proto = out.get("protocol", "")
    settings = out.get("settings", {})
    stream = out.get("streamSettings", {})
    sec = stream.get("security", "none")

    if proto == "vless":
        vnext = settings.get("vnext", [])
        if not vnext or not vnext[0].get("users"):
            return False, "vless_no_user"
        if len(vnext[0]["users"][0].get("id", "")) < 32:
            return False, "vless_bad_uuid"

    if sec == "reality":
        rs = stream.get("realitySettings", {})
        if not rs.get("publicKey"):
            return False, "reality_no_pbk"
        if not rs.get("serverName"):
            return False, "reality_no_sni"

    return True, ""


def debug_one(key: str, idx: int):
    print(f"\n{'=' * 70}")
    print(f"KEY #{idx}")
    print(f"FULL: {key}")
    print(f"LEN:  {len(key)}")

    port = get_free_port()
    cfg = build_xray_config(key, port)
    if not cfg:
        print("❌ build_xray_config -> None")
        return

    ok, reason = validate_config(cfg)
    print(f"\nVALIDATE: {'✅ OK' if ok else '❌ ' + reason}")

    print(f"\nCONFIG JSON:\n{json.dumps(cfg, indent=2, ensure_ascii=False)}")

    if not ok:
        print("⏭  Xray не запускаем — конфиг невалиден по нашей проверке")
        return

    tmpdir = tempfile.mkdtemp(prefix="xray_dbg_")
    cfg_path = os.path.join(tmpdir, "config.json")
    with open(cfg_path, "w") as f:
        json.dump(cfg, f)

    proc = subprocess.Popen(
        [XRAY_BIN, "-c", cfg_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    time.sleep(2.5)

    if proc.poll() is not None:
        out = proc.stdout.read() or ""
        print(f"\n❌ Xray exited code={proc.returncode}")
        print(f"FULL STDERR/STDOUT:\n{out}")
    else:
        print(f"\n✅ Xray running on port {port}")
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()

    shutil.rmtree(tmpdir, ignore_errors=True)


def main():
    if not os.path.exists(XRAY_BIN):
        print(f"❌ XRAY_BIN not found: {XRAY_BIN}")
        sys.exit(1)

    r = subprocess.run([XRAY_BIN, "version"], capture_output=True, text=True)
    print(f"Xray binary: {XRAY_BIN}")
    print(f"Xray version:\n{r.stdout}{r.stderr}")

    print(f"\n📥 Загрузка ключей из {SRC}...")
    text = requests.get(SRC, timeout=30).text
    keys = [l.strip() for l in text.split("\n") if l.strip().startswith("vless://")]
    print(f"Всего VLESS-ключей: {len(keys)}")

    if not keys:
        print("❌ Нет ключей")
        sys.exit(1)

    for i, k in enumerate(keys[:5], 1):
        debug_one(k, i)


if __name__ == "__main__":
    main()
