from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from scanners.nmap_scan import _run_nmap


def trace_route(target: str) -> list[dict[str, Any]]:
    xml_text = _run_nmap(["-sn", "--traceroute", "-n", "-oX", "-", target])
    root = ET.fromstring(xml_text)

    hops: list[dict[str, Any]] = []
    for hop in root.findall(".//trace/hop"):
        hops.append(
            {
                "ttl": int(hop.attrib.get("ttl", "0")),
                "ip": hop.attrib.get("ipaddr"),
                "rtt": float(hop.attrib.get("rtt", "0")) if hop.attrib.get("rtt") else None,
                "host": hop.attrib.get("host"),
            }
        )

    hops.sort(key=lambda item: item["ttl"])
    return hops
