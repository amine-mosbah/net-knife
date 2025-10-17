#!/usr/bin/env python3
"""
PoC async TCP connect scanner (plain text streaming).
Save as netknife_poc.py and run: python3 netknife_poc.py 192.168.1.0/28 --ports 22-1024 --concurrency 200
"""

import asyncio
import argparse
import ipaddress
import socket
from typing import List, Iterable
import sys

DEFAULT_PORTS = "1-1024"

def parse_ports(range_str: str) -> List[int]:
    parts = range_str.split(",")
    ports = set()
    for p in parts:
        if "-" in p:
            a, b = p.split("-", 1)
            ports.update(range(int(a), int(b)+1))
        else:
            ports.add(int(p))
    return sorted([pt for pt in ports if 1 <= pt <= 65535])

def expand_targets(target: str) -> Iterable[str]:
    # If CIDR
    try:
        if "/" in target:
            net = ipaddress.ip_network(target, strict=False)
            for ip in net.hosts():
                yield str(ip)
            return
        # If single IP
        ipaddress.ip_address(target)
        yield target
        return
    except ValueError:
        # Try resolve as hostname
        try:
            infos = socket.getaddrinfo(target, None)
            seen = set()
            for info in infos:
                addr = info[4][0]
                if addr not in seen:
                    seen.add(addr)
                    yield addr
            return
        except Exception:
            raise

async def try_connect(semaphore: asyncio.Semaphore, ip: str, port: int, timeout: float=3.0):
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
            # Connected
            banner = b""
            try:
                # try to read small banner (non-blocking)
                writer.write(b"\r\n")
                await writer.drain()
                await asyncio.sleep(0.1)
                if not reader.at_eof():
                    banner = await asyncio.wait_for(reader.read(1024), timeout=0.5)
            except Exception:
                pass
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            banner_text = (" " + banner.decode(errors="replace").strip()) if banner else ""
            print(f"[OPEN] {ip}:{port}{banner_text}")
            sys.stdout.flush()
            return (ip, port, True, banner_text)
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            # closed or filtered
            return (ip, port, False, "")
        except Exception as e:
            # Unexpected
            return (ip, port, False, "")

async def scan_targets(targets: List[str], ports: List[int], concurrency: int):
    sem = asyncio.Semaphore(concurrency)
    tasks = []
    for ip in targets:
        for p in ports:
            tasks.append(try_connect(sem, ip, p))
    # Run tasks with progress streaming
    for fut in asyncio.as_completed(tasks):
        await fut  # try_connect prints results directly

def main():
    parser = argparse.ArgumentParser(description="NetKnife PoC TCP connect scanner (async).")
    parser.add_argument("target", help="IP, CIDR, or hostname (e.g., 192.168.1.0/28 or example.com)")
    parser.add_argument("--ports", default=DEFAULT_PORTS, help="Port list like 22,80,443 or range 1-1024")
    parser.add_argument("--concurrency", type=int, default=200, help="Max concurrent connections")
    args = parser.parse_args()

    ports = parse_ports(args.ports)
    # expand targets
    try:
        targets = list(expand_targets(args.target))
    except Exception as e:
        print("Error resolving target:", e)
        return

    print(f"Scanning {len(targets)} target(s) × {len(ports)} ports (concurrency={args.concurrency})")
    asyncio.run(scan_targets(targets, ports, args.concurrency))

if __name__ == "__main__":
    main()
