from __future__ import annotations

import os
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


def _resolve_nmap_executable() -> str:
    env_path = os.environ.get("NMAP_PATH")
    if env_path:
        candidate = Path(env_path)
        if candidate.is_file():
            return str(candidate)

    detected = shutil.which("nmap")
    if detected:
        return detected

    common_dirs = [
        Path(r"C:\Program Files (x86)\Nmap\nmap.exe"),
        Path(r"C:\Program Files\Nmap\nmap.exe"),
        Path(r"D:\Program Files (x86)\Nmap\nmap.exe"),
        Path(r"D:\Program Files\Nmap\nmap.exe"),
        Path(r"E:\Program Files (x86)\Nmap\nmap.exe"),
        Path(r"E:\Program Files\Nmap\nmap.exe"),
        Path(r"F:\Program Files (x86)\Nmap\nmap.exe"),
        Path(r"F:\Program Files\Nmap\nmap.exe"),
    ]
    for candidate in common_dirs:
        if candidate.is_file():
            return str(candidate)

    raise RuntimeError(
        "未检测到 nmap，请先安装 Nmap 并确保命令在 PATH 中可用，"
        "或设置环境变量 NMAP_PATH 指向 nmap.exe。"
    )


def _run_nmap(args: list[str]) -> str:
    command = [_resolve_nmap_executable(), *args]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip() or exc.stdout.strip() or "Nmap 执行失败。"
        raise RuntimeError(stderr) from exc
    return completed.stdout


def scan_ports(target: str, top_ports: int = 30) -> list[dict[str, Any]]:
    xml_text = _run_nmap(["-Pn", "-sV", "--top-ports", str(top_ports), "-oX", "-", target])
    root = ET.fromstring(xml_text)

    ports: list[dict[str, Any]] = []
    for port in root.findall(".//host/ports/port"):
        state = port.find("state")
        service = port.find("service")
        ports.append(
            {
                "port": int(port.attrib.get("portid", "0")),
                "protocol": port.attrib.get("protocol"),
                "state": state.attrib.get("state") if state is not None else None,
                "service": service.attrib.get("name") if service is not None else None,
                "product": service.attrib.get("product") if service is not None else None,
                "version": service.attrib.get("version") if service is not None else None,
                "extrainfo": service.attrib.get("extrainfo") if service is not None else None,
            }
        )

    ports.sort(key=lambda item: item["port"])
    return ports
