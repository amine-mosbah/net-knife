# modules/service_probes/http_probe.py
import asyncio
from .common import read_nonblocking, fmt_banner

async def probe_http(ip: str, port: int, host_header: str | None = None, https: bool = False, timeout: float = 1.5):
    # Plain TCP HTTP probe (no TLS for now; TLS detection will be separate)
    req_host = host_header or ip
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        payload = (f"GET / HTTP/1.1\r\nHost: {req_host}\r\nUser-Agent: NetKnife/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n").encode()
        writer.write(payload)
        await writer.drain()
        data = await read_nonblocking(reader, n=2048, timeout=timeout)
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        # First line / headers
        head = (data or b"").split(b"\r\n\r\n", 1)[0][:1024]
        text = head.decode(errors="replace")
        # Try to parse Server header and status
        status_line = text.splitlines()[0] if text else ""
        server = ""
        for line in text.splitlines():
            if line.lower().startswith("server:"):
                server = line.split(":", 1)[1].strip()
                break
        summary = f"HTTP({port}) {status_line} " + (f"[Server: {server}]" if server else "")
        return True, summary.strip()
    except Exception:
        return False, ""
