from __future__ import annotations
#规则引擎判断（生成、结论、建议动作）
from typing import Any


ENTERPRISE_ROLES = [
    "自动识别",
    "办公终端",
    "网关/路由器",
    "DNS服务器",
    "Web站点",
    "打印机",
    "NAS/文件服务器",
    "交换机/AP",
    "数据库/应用服务器",
]


def _format_port_brief(open_ports: list[dict[str, Any]], limit: int = 5) -> str:
    if not open_ports:
        return "无"

    snippets = []
    for item in open_ports[:limit]:
        service = item.get("service") or "unknown"
        snippets.append(f'{item["port"]}/{item["protocol"]}({service})')
    if len(open_ports) > limit:
        snippets.append(f"... 共 {len(open_ports)} 个")
    return ", ".join(snippets)


def _dns_service_signal(
    target: str,
    dns_server: str,
    dns_ok: bool,
    open_ports: list[dict[str, Any]],
    object_role: str,
) -> bool:
    if not dns_ok:
        return False

    normalized_target = target.strip().lower()
    normalized_dns_server = dns_server.strip().lower()
    if normalized_target and normalized_target == normalized_dns_server:
        return True

    if object_role == "DNS服务器":
        return True

    return any(item["port"] == 53 for item in open_ports)


def analyze_host_result(result: dict[str, Any]) -> dict[str, Any]:
    summary = result["summary"]
    dns_result = result["dns"]
    ports = result["ports"]
    hops = result["hops"]
    object_role = result.get("object_role", "自动识别")

    open_ports = [item for item in ports if item.get("state") == "open"]
    open_port_count = len(open_ports)
    icmp_up = summary["received"] > 0
    traceroute_ok = len(hops) > 0
    dns_ok = bool(dns_result["ok"])
    dns_service_ok = _dns_service_signal(
        target=result["target"],
        dns_server=result["dns_server"],
        dns_ok=dns_ok,
        open_ports=open_ports,
        object_role=object_role,
    )
    service_reachable = open_port_count > 0 or dns_service_ok

    if icmp_up:
        availability = {
            "code": "online",
            "label": "在线",
            "reason": f'ICMP 收到 {summary["received"]}/{summary["sent"]} 个回包。',
        }
    elif service_reachable:
        availability = {
            "code": "service_reachable",
            "label": "服务在线",
            "reason": "ICMP 未收到回包，但业务端口或关键服务仍可访问。",
        }
    elif traceroute_ok:
        availability = {
            "code": "route_reachable",
            "label": "路径可达",
            "reason": "未收到 ICMP 回包，但 traceroute 发现了到目标的路径信息。",
        }
    else:
        availability = {
            "code": "unreachable",
            "label": "离线",
            "reason": "ICMP、业务端口和路由追踪都未提供可达证据。",
        }

    findings: list[str] = []
    recommendations: list[str] = []
    tags: list[str] = []

    if icmp_up:
        findings.append(
            f'ICMP 探测成功，平均时延 {summary["avg_ms"]} ms，丢包率 {summary["loss_rate"]}%。'
        )
    else:
        findings.append("ICMP 探测未收到回包。")
        tags.append("icmp_unreachable")

    if 0 < summary["loss_rate"] < 100:
        findings.append(f'存在 {summary["loss_rate"]}% 的丢包，链路可能不稳定。')
        recommendations.append("建议增加 ping 次数并结合链路质量、交换机端口错误计数做进一步排查。")

    if open_port_count > 0:
        findings.append(f"识别到开放端口：{_format_port_brief(open_ports)}。")
    else:
        findings.append("在当前扫描端口范围内未识别到开放端口。")

    if dns_ok:
        findings.append(
            f'DNS 检测成功，响应时间 {dns_result["response_ms"]} ms，结果 {", ".join(dns_result["answers"]) or "无"}。'
        )
    else:
        findings.append("DNS 检测未返回有效解析结果。")

    if traceroute_ok:
        findings.append(f"获取到 {len(hops)} 跳路由信息。")
    else:
        findings.append("未获取到 traceroute 结果。")

    if availability["code"] == "online" and open_port_count > 0:
        diagnosis_summary = "目标主机在线且存在可识别服务，连通性与业务可达性均正常。"
        recommendations.append("建议继续关注端口暴露面和服务版本信息，完善资产台账。")
    elif availability["code"] == "online":
        diagnosis_summary = "目标主机在线，但在当前扫描范围内未发现开放端口。"
        recommendations.append("如需识别更多服务，可扩大 Nmap 扫描端口范围或指定业务端口。")
    elif availability["code"] == "service_reachable":
        diagnosis_summary = "目标可能屏蔽了 ICMP，但业务端口或关键服务仍然可访问。"
        tags.append("service_reachable_icmp_blocked")
        recommendations.append("建议结合业务端口、ACL 和防火墙策略判断是否存在禁 ping 配置。")
    elif availability["code"] == "route_reachable":
        diagnosis_summary = "目标未响应 ICMP，但路径上仍存在可达迹象，可能是终端或边界设备限制。"
        tags.append("route_only")
        recommendations.append("建议使用已知业务端口、应用协议或终端日志做二次验证。")
    else:
        diagnosis_summary = "目标当前不可达，或被防火墙/ACL/主机策略限制。"
        tags.append("target_unreachable")
        recommendations.append("建议优先检查目标地址、网关、ACL、防火墙和本机权限设置。")

    if not traceroute_ok:
        recommendations.append("如需更稳定的路由分析，可使用管理员权限运行，并尝试更换支持 traceroute 的目标。")

    if not dns_ok:
        recommendations.append("建议核对 DNS 服务器地址和测试域名，避免因空值或不可达服务器导致误判。")

    if result["errors"]:
        recommendations.append("当前存在执行错误，请先处理依赖或权限问题后再复测。")

    signal_table = [
        {"signal": "ICMP 回包", "status": "成功" if icmp_up else "失败", "detail": f'{summary["received"]}/{summary["sent"]}'},
        {"signal": "开放端口", "status": "成功" if open_port_count > 0 else "失败", "detail": _format_port_brief(open_ports)},
        {"signal": "DNS 检测", "status": "成功" if dns_ok else "失败", "detail": f'{dns_result["response_ms"]} ms' if dns_result["response_ms"] is not None else "N/A"},
        {"signal": "路由追踪", "status": "成功" if traceroute_ok else "失败", "detail": f"{len(hops)} hops"},
    ]

    result["availability"] = availability
    result["diagnosis"] = {
        "summary": diagnosis_summary,
        "findings": findings,
        "recommendations": recommendations,
        "tags": tags,
        "signal_table": signal_table,
        "open_port_count": open_port_count,
        "service_reachable": service_reachable,
        "dns_service_ok": dns_service_ok,
    }
    return result


def build_batch_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {
        "online": 0,
        "service_reachable": 0,
        "route_reachable": 0,
        "unreachable": 0,
    }
    for item in results:
        counts[item["availability"]["code"]] += 1

    return {
        "total": len(results),
        "online": counts["online"],
        "service_reachable": counts["service_reachable"],
        "route_reachable": counts["route_reachable"],
        "unreachable": counts["unreachable"],
    }
