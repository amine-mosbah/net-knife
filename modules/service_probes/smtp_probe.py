# modules/service_probes/smtp_probe.py
import asyncio
from .common import read_nonblocking

async def probe_smtp(ip: str, port: int, helo_host: str = "netknife.local", timeout: float = 1.5):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        banner = await read_nonblocking(reader, n=1024, timeout=timeout)
        writer.write(f"EHLO {helo_host}\r\n".encode())
        await writer.drain()
        resp = await read_nonblocking(reader, n=1024, timeout=timeout)
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        summary = f"SMTP({port}) banner={banner.decode(errors='replace').strip()} EHLO={resp.decode(errors='replace').strip()}"
        return True, summary
    except Exception:
        return False, ""
