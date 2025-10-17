# modules/service_probes/common.py
import asyncio

async def read_nonblocking(reader: asyncio.StreamReader, n=1024, timeout=0.4):
    try:
        return await asyncio.wait_for(reader.read(n), timeout=timeout)
    except Exception:
        return b""

def fmt_banner(proto: str, data: bytes) -> str:
    s = (data or b"").decode(errors="replace").strip()
    return f"{proto} banner: {s}" if s else ""
