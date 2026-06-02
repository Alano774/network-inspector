from __future__ import annotations

import socket
from typing import Any

from scapy.all import ARP, Ether, conf, srp


conf.verb = 0


def _resolve_hostname(ip_address: str) -> str | None:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except OSError:
        return None


def arp_scan(cidr: str, timeout: int = 2) -> list[dict[str, Any]]:
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
    answered, _ = srp(packet, timeout=timeout, verbose=0)

    devices: list[dict[str, Any]] = []
    for _, reply in answered:
        devices.append(
            {
                "ip": reply.psrc,
                "mac": reply.hwsrc,
                "hostname": _resolve_hostname(reply.psrc),
            }
        )

    devices.sort(key=lambda item: tuple(int(part) for part in item["ip"].split(".")))
    return devices
