from __future__ import annotations

import time
from typing import Any

from scapy.all import ICMP, IP, conf, sr1


conf.verb = 0


def ping_stats(target: str, count: int = 4, timeout: int = 1) -> dict[str, Any]:
    rtts: list[float] = []

    for _ in range(count):
        start = time.perf_counter()
        reply = sr1(IP(dst=target) / ICMP(), timeout=timeout, verbose=0)
        if reply is not None:
            rtts.append(round((time.perf_counter() - start) * 1000, 2))

    sent = count
    received = len(rtts)
    loss_rate = round(((sent - received) / sent) * 100, 2)

    return {
        "sent": sent,
        "received": received,
        "loss_rate": loss_rate,
        "avg_ms": round(sum(rtts) / received, 2) if received else None,
        "min_ms": min(rtts) if rtts else None,
        "max_ms": max(rtts) if rtts else None,
        "samples": rtts,
        "is_up": received > 0,
    }
