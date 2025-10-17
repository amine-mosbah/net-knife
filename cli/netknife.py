#!/usr/bin/env python3
"""
NetKnife CLI - interactive menu scaffold + python version assertion.

Run: python3 cli/netknife.py
"""

import sys
import os
import argparse
import asyncio
import shutil
from pathlib import Path
from typing import Optional, Dict

# ---------------------------
# Python version assertion
# ---------------------------
MIN_PY = (3, 11)
MAX_PY = (3, 13)  # exclusive upper bound (so 3.13 is not allowed)

if not (sys.version_info >= MIN_PY and sys.version_info < MAX_PY):
    sys.stderr.write(
        f"ERROR: NetKnife requires Python >= {MIN_PY[0]}.{MIN_PY[1]} and < {MAX_PY[0]}.{MAX_PY[1]}\n"
        f"You are running Python {sys.version_info.major}.{sys.version_info.minor}.\n"
        "Please install a compatible Python version (pyenv recommended).\n"
    )
    sys.exit(2)

# ---------------------------
# Basic configuration & helpers
# ---------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[1]
SESSION_DIR = Path.home() / ".local" / "share" / "netknife" / "sessions"
SESSION_DIR.mkdir(parents=True, exist_ok=True)

DEFAULTS: Dict[str, object] = {
    "concurrency": 200,
    "ports": "1-1024",
    "timeout": 3.0,
    "use_prompt_toolkit": True,
}
# override with env var if set
DEFAULTS["concurrency"] = int(os.getenv("NETKNIFE_CONCURRENCY", DEFAULTS["concurrency"]))

# ---------------------------
# Import optional nice UI lib
# ---------------------------
USE_PROMPT_TOOLKIT = False
try:
    from prompt_toolkit import prompt
    from prompt_toolkit.completion import WordCompleter
    USE_PROMPT_TOOLKIT = True
except Exception:
    USE_PROMPT_TOOLKIT = False

# ---------------------------
# Import our scanning module (PoC)
# ---------------------------
# We'll import the helper tcp scanner module (you can also ship it as a package)
try:
    # prefer local module path
    import importlib.util
    tcp_scan_path = PROJECT_ROOT / "modules" / "py_tcp_scan" / "tcp_scan.py"
    if tcp_scan_path.exists():
        spec = importlib.util.spec_from_file_location("tcp_scan", str(tcp_scan_path))
        tcp_scan = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tcp_scan)  # type: ignore
    else:
        tcp_scan = None
except Exception as e:
    tcp_scan = None

# ---------------------------
# CLI helper functions
# ---------------------------
def clear_screen():
    if shutil.which("clear"):
        os.system("clear")

def header():
    print("=" * 60)
    print("NetKnife — interactive network scanner (CLI scaffold)")
    print("Python version:", f"{sys.version_info.major}.{sys.version_info.minor}")
    print("Session dir:", SESSION_DIR)
    print("=" * 60)

def print_settings():
    print("Current settings:")
    print(f"  Concurrency: {DEFAULTS['concurrency']}")
    print(f"  Port range:  {DEFAULTS['ports']}")
    print(f"  Timeout:     {DEFAULTS['timeout']}s")
    print("")

# ---------------------------
# Menu actions (hooks)
# ---------------------------
async def action_tcp_connect_scan():
    if tcp_scan is None:
        print("[!] tcp_scan module not found. Please create modules/py_tcp_scan/tcp_scan.py")
        return
    # get target from user
    target = input("Target (IP, CIDR, or hostname): ").strip()
    if not target:
        print("No target provided.")
        return
    ports = input(f"Ports [{DEFAULTS['ports']}]: ").strip() or DEFAULTS['ports']
    concurrency = input(f"Concurrency [{DEFAULTS['concurrency']}]: ").strip()
    concurrency = int(concurrency) if concurrency else DEFAULTS["concurrency"]
    timeout = input(f"Timeout seconds [{DEFAULTS['timeout']}]: ").strip()
    timeout = float(timeout) if timeout else float(DEFAULTS["timeout"])
    print(f"Starting TCP connect scan -> {target} ports={ports} concurrency={concurrency} timeout={timeout}")
    # run the async scan implemented in tcp_scan.py
    await tcp_scan.run_scan(target, ports, concurrency, timeout)

def action_masscan_wrapper():
    print("[masscan wrapper] Not implemented yet. This will call masscan if installed.")
    if shutil.which("masscan") is None:
        print("masscan not found on PATH. Install masscan or add wrapper.")
    else:
        print("masscan found. (Wrapper placeholder)")

def action_nmap_wrapper():
    print("[nmap wrapper] Not implemented yet. This will call nmap if installed.")
    if shutil.which("nmap") is None:
        print("nmap not found on PATH. Install nmap if desired.")
    else:
        print("nmap found. (Wrapper placeholder)")

def action_settings_menu():
    print("Settings (press Enter to keep current):")
    ports = input(f"Port range [{DEFAULTS['ports']}]: ").strip() or DEFAULTS["ports"]
    concurrency = input(f"Concurrency [{DEFAULTS['concurrency']}]: ").strip()
    concurrency = int(concurrency) if concurrency else DEFAULTS["concurrency"]
    timeout = input(f"Timeout seconds [{DEFAULTS['timeout']}]: ").strip()
    timeout = float(timeout) if timeout else DEFAULTS["timeout"]
    DEFAULTS["ports"] = ports
    DEFAULTS["concurrency"] = concurrency
    DEFAULTS["timeout"] = timeout
    print("Settings updated.")
    print_settings()

# ---------------------------
# Menu engine
# ---------------------------
MENU_ITEMS = [
    ("1", "TCP Connect scan (safe, non-root)", action_tcp_connect_scan),
    ("2", "Run masscan (fast)", action_masscan_wrapper),
    ("3", "Run nmap (wrapper)", action_nmap_wrapper),
    ("4", "Settings", action_settings_menu),
    ("5", "Exit", None),
]

async def run_menu_loop():
    while True:
        clear_screen()
        header()
        print_settings()
        print("Select an option:")
        for k, label, _ in MENU_ITEMS:
            print(f"  {k}. {label}")
        print("")
        choice = ""
        if USE_PROMPT_TOOLKIT and DEFAULTS.get("use_prompt_toolkit", True):
            completer = WordCompleter([k for k, _, _ in MENU_ITEMS], ignore_case=True)
            try:
                choice = prompt("Choice> ", completer=completer).strip()
            except KeyboardInterrupt:
                print("\nInterrupted. Exiting.")
                return
        else:
            try:
                choice = input("Choice> ").strip()
            except KeyboardInterrupt:
                print("\nInterrupted. Exiting.")
                return

        matched = [item for item in MENU_ITEMS if item[0] == choice]
        if not matched:
            print("Invalid choice. Press Enter to continue...")
            input()
            continue
        if choice == "5":
            print("Goodbye.")
            return
        # call the action (may be async)
        action = matched[0][2]
        if asyncio.iscoroutinefunction(action):
            await action()
        else:
            # run sync action inside executor if we want to keep UI responsive
            result = action()
            # if action returned an awaitable, await it
            if asyncio.iscoroutine(result):
                await result
        print("\nScan/Action finished. Press Enter to return to menu...")
        input()

# ---------------------------
# CLI entrypoint
# ---------------------------
def main():
    parser = argparse.ArgumentParser(description="NetKnife CLI scaffold")
    parser.add_argument("--no-prompt-toolkit", action="store_true", help="Disable fancy interactive menu")
    args = parser.parse_args()
    if args.no_prompt_toolkit:
        DEFAULTS["use_prompt_toolkit"] = False

    try:
        asyncio.run(run_menu_loop())
    except KeyboardInterrupt:
        print("\nExiting...")

if __name__ == "__main__":
    main()
