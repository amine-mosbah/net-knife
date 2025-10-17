# modules/py_tcp_scan/tcp_scan.py
import asyncio
import ipaddress
import socket
import sys
from typing import Iterable, List

DEFAULT_PORTS = "1-1024"

def parse_ports(range_str: str) -> List[int]:
    parts = range_str.split(",")
    ports = set()
    for p in parts:
        p = p.strip()
        if not p:
            continue
        if "-" in p:
            a, b = p.split("-", 1)
            ports.update(range(int(a), int(b)+1))
        else:
            ports.add(int(p))
    return sorted([pt for pt in ports if 1 <= pt <= 65535])

def expand_targets(target: str) -> Iterable[str]:
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
        infos = socket.getaddrinfo(target, None)
        seen = set()
        for info in infos:
            addr = info[4][0]
            if addr not in seen:
                seen.add(addr)
                yield addr
        return

async def try_connect(semaphore: asyncio.Semaphore, ip: str, port: int, timeout: float=3.0):
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
            banner = b""
            try:
                writer.write(b"\r\n")
                await writer.drain()
                await asyncio.sleep(0.08)
                if not reader.at_eof():
                    banner = await asyncio.wait_for(reader.read(1024), timeout=0.3)
            except Exception:
                pass
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            banner_text = (" " + banner.decode(errors="replace").strip()) if banner else ""
            print(f"[OPEN] {ip}:{port}{banner_text}")
            sys.stdout.flush()
            return (ip, port, True, banner_text)
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return (ip, port, False, "")
        except Exception:
            return (ip, port, False, "")

async def run_scan_async(targets: List[str], ports: List[int], concurrency: int, timeout: float):
    sem = asyncio.Semaphore(concurrency)
    tasks = []
    for ip in targets:
        for p in ports:
            tasks.append(try_connect(sem, ip, p, timeout=timeout))
    # Use as_completed to stream results as they arrive
    for fut in asyncio.as_completed(tasks):
        await fut  # try_connect prints directly

def run_scan(target: str, ports: str = DEFAULT_PORTS, concurrency: int = 200, timeout: float = 3.0):
    ports_list = parse_ports(ports)
    try:
        targets = list(expand_targets(target))
    except Exception as e:
        print("Error resolving target:", e)
        return
    total = len(targets) * len(ports_list)
    print(f"Scanning {len(targets)} target(s) × {len(ports_list)} ports (total {total})")
    asyncio.run(run_scan_async(targets, ports_list, concurrency, timeout))
