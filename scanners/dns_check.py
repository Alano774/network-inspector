from __future__ import annotations

import time
from typing import Any

from scapy.all import DNS, DNSQR, IP, UDP, conf, sr1
from scapy.packet import NoPayload


conf.verb = 0


def dns_check(dns_server: str, domain: str, timeout: int = 2) -> dict[str, Any]:
    start = time.perf_counter()
    reply = sr1(
        IP(dst=dns_server) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain)),
        timeout=timeout,
        verbose=0,
    )
    response_ms = round((time.perf_counter() - start) * 1000, 2)

    if reply is None or not reply.haslayer(DNS):
        return {"ok": False, "response_ms": response_ms, "answers": []}

    dns_layer = reply.getlayer(DNS)
    answers: list[str] = []
    record = dns_layer.an

    for _ in range(dns_layer.ancount):
        if record is None:
            break
        answer = getattr(record, "rdata", "")
        if isinstance(answer, bytes):
            answer = answer.decode(errors="ignore")
        answers.append(str(answer))
        payload = getattr(record, "payload", None)
        if payload is None or isinstance(payload, NoPayload):
            break
        record = payload

    return {"ok": dns_layer.ancount > 0, "response_ms": response_ms, "answers": answers}
