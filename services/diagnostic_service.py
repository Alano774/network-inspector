from __future__ import annotations

from datetime import datetime
from typing import Any, Callable

from services.diagnosis_rules import analyze_host_result, build_batch_summary
from scanners.arp_scan import arp_scan
from scanners.dns_check import dns_check
from scanners.icmp_ping import ping_stats
from scanners.nmap_scan import scan_ports
from scanners.trace_route import trace_route


def _timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _safe_call(
    func: Callable[..., Any],
    errors: list[str],
    warnings: list[str],
    friendly_name: str,
    default: Any,
    *args: Any,
    **kwargs: Any,
) -> Any:
    try:
        return func(*args, **kwargs)
    except PermissionError:
        message = f"{friendly_name} 执行失败：当前权限不足，请尝试使用管理员权限运行。"
        errors.append(message)
        return default
    except RuntimeError as exc:
        errors.append(f"{friendly_name} 执行失败：{exc}")
        return default
    except Exception as exc:  # pragma: no cover - defensive guard for live networking
        warnings.append(f"{friendly_name} 返回异常：{exc}")
        return default


def run_host_diagnostic(
    target: str,
    dns_server: str,
    dns_domain: str,
    ping_count: int = 4,
    top_ports: int = 30,
    object_label: str | None = None,
    object_role: str = "自动识别",
) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []

    summary = _safe_call(
        ping_stats,
        errors,
        warnings,
        "ICMP 探测",
        {
            "sent": ping_count,
            "received": 0,
            "loss_rate": 100.0,
            "avg_ms": None,
            "min_ms": None,
            "max_ms": None,
            "samples": [],
            "is_up": False,
        },
        target,
        ping_count,
        1,
    )

    dns_result = _safe_call(
        dns_check,
        errors,
        warnings,
        "DNS 检测",
        {"ok": False, "response_ms": None, "answers": []},
        dns_server,
        dns_domain,
        2,
    )

    ports = _safe_call(scan_ports, errors, warnings, "Nmap 端口扫描", [], target, top_ports)
    hops = _safe_call(trace_route, errors, warnings, "路由追踪", [], target)

    result = {
        "scan_type": "host_diagnostic",
        "target": target,
        "object_label": object_label or target,
        "object_role": object_role,
        "dns_server": dns_server,
        "dns_domain": dns_domain,
        "created_at": _timestamp(),
        "summary": summary,
        "dns": dns_result,
        "ports": ports,
        "hops": hops,
        "errors": errors,
        "warnings": warnings,
    }
    return analyze_host_result(result)


def run_batch_diagnostic(
    items: list[dict[str, Any]],
    ping_count: int = 4,
    top_ports: int = 30,
) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    batch_errors: list[str] = []

    for item in items:
        try:
            results.append(
                run_host_diagnostic(
                    target=item["target"],
                    dns_server=item["dns_server"],
                    dns_domain=item["dns_domain"],
                    ping_count=ping_count,
                    top_ports=top_ports,
                    object_label=item.get("label"),
                    object_role=item.get("object_role", "自动识别"),
                )
            )
        except Exception as exc:  # pragma: no cover - defensive guard for live networking
            batch_errors.append(f'{item.get("label", item["target"])} 扫描失败：{exc}')

    return {
        "scan_type": "batch_diagnostic",
        "created_at": _timestamp(),
        "results": results,
        "summary": build_batch_summary(results),
        "errors": batch_errors,
    }


def hydrate_host_result_from_detail(detail: dict[str, Any]) -> dict[str, Any]:
    host_result = detail["host_result"]
    result = {
        "scan_type": "host_diagnostic",
        "target": host_result["target"],
        "object_label": host_result["target"],
        "object_role": "自动识别",
        "dns_server": host_result["dns_server"],
        "dns_domain": host_result["dns_domain"],
        "created_at": detail["created_at"],
        "summary": {
            "sent": host_result["sent"],
            "received": host_result["received"],
            "loss_rate": host_result["loss_rate"],
            "avg_ms": host_result["avg_ms"],
            "min_ms": host_result["min_ms"],
            "max_ms": host_result["max_ms"],
            "samples": [],
            "is_up": bool(host_result["is_up"]),
        },
        "dns": {
            "ok": bool(host_result["dns_ok"]),
            "response_ms": host_result["dns_ms"],
            "answers": host_result["dns_answers"],
        },
        "ports": detail["ports"],
        "hops": detail["hops"],
        "errors": host_result["errors_json"],
        "warnings": host_result["warnings_json"],
    }
    return analyze_host_result(result)


def run_lan_discovery(cidr: str, timeout: int = 2) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    devices = _safe_call(arp_scan, errors, warnings, "ARP 扫描", [], cidr, timeout)

    return {
        "scan_type": "lan_discovery",
        "cidr": cidr,
        "created_at": _timestamp(),
        "devices": devices,
        "errors": errors,
        "warnings": warnings,
    }
