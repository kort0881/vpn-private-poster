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
from advanced_checker import (
    build_xray_config,
    get_free_port,
    mask_key,
    XRAY_BIN,
)

SRC = "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/refs/heads/main/data/githubmirror/clean/vless.txt"


def debug_one(key: str):
    print(f"\n{'=' * 70}")
    print(f"KEY: {mask_key(key)}")
    print(f"RAW: {key[:120]}")

    port = get_free_port()
    cfg = build_xray_config(key, port)
    if not cfg:
        print("❌ build_xray_config -> None")
        return

    print(f"\nCONFIG JSON:\n{json.dumps(cfg, indent=2)}")

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
        print(f"FULL OUTPUT:\n{out}")
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

    for k in keys[:5]:
        debug_one(k)


if __name__ == "__main__":
    main()
