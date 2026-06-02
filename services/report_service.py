from __future__ import annotations

import csv
import io
import re
import time
from collections import defaultdict
from pathlib import Path
from typing import Any


def _safe_name(raw_value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", raw_value).strip("_") or "scan"


def _to_csv_text(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return ""

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def _bundle_metadata(base_name: str, created_at: str) -> dict[str, str]:
    report_date = created_at.split(" ")[0]
    return {"base_name": base_name, "report_date": report_date}


def _iter_report_groups(report_dir: Path) -> list[dict[str, Any]]:
    grouped: dict[str, list[Path]] = defaultdict(list)
    for file_path in report_dir.rglob("*"):
        if not file_path.is_file():
            continue
        if file_path.name.startswith("."):
            continue
        group_key = str(file_path.relative_to(report_dir).with_suffix(""))
        grouped[group_key].append(file_path)

    groups = []
    for group_key, files in grouped.items():
        latest_mtime = max(item.stat().st_mtime for item in files)
        groups.append({"key": group_key, "files": files, "latest_mtime": latest_mtime})
    return groups


def _cleanup_empty_dirs(report_dir: Path) -> None:
    for directory in sorted(
        [item for item in report_dir.rglob("*") if item.is_dir()],
        key=lambda item: len(item.parts),
        reverse=True,
    ):
        try:
            next(directory.iterdir())
        except StopIteration:
            directory.rmdir()


def _delete_group(group: dict[str, Any]) -> None:
    for file_path in group["files"]:
        if file_path.exists():
            file_path.unlink()


def cleanup_saved_reports(
    report_dir: Path,
    retention_days: int = 30,
    retention_groups: int = 100,
) -> dict[str, int]:
    report_dir.mkdir(parents=True, exist_ok=True)
    removed_by_age = 0
    removed_by_count = 0

    if retention_days > 0:
        cutoff = time.time() - retention_days * 24 * 60 * 60
        groups = _iter_report_groups(report_dir)
        for group in groups:
            if group["latest_mtime"] < cutoff:
                _delete_group(group)
                removed_by_age += 1

    groups = sorted(_iter_report_groups(report_dir), key=lambda item: item["latest_mtime"], reverse=True)
    if retention_groups > 0 and len(groups) > retention_groups:
        for group in groups[retention_groups:]:
            _delete_group(group)
            removed_by_count += 1

    _cleanup_empty_dirs(report_dir)
    return {"removed_by_age": removed_by_age, "removed_by_count": removed_by_count}


def save_report_bundle(
    bundle: dict[str, str],
    report_dir: Path,
    retention_days: int = 30,
    retention_groups: int = 100,
) -> dict[str, Any]:
    date_dir = report_dir / bundle["report_date"]
    date_dir.mkdir(parents=True, exist_ok=True)

    markdown_path = date_dir / f'{bundle["base_name"]}.md'
    csv_path = date_dir / f'{bundle["base_name"]}.csv'
    markdown_path.write_text(bundle["markdown_text"], encoding="utf-8")
    csv_path.write_text(bundle["csv_text"], encoding="utf-8-sig")

    cleanup_result = cleanup_saved_reports(
        report_dir=report_dir,
        retention_days=retention_days,
        retention_groups=retention_groups,
    )
    return {
        "markdown_path": str(markdown_path),
        "csv_path": str(csv_path),
        "retention_days": retention_days,
        "retention_groups": retention_groups,
        **cleanup_result,
    }


def build_host_report_bundle(result: dict[str, Any], report_dir: Path) -> dict[str, str]:
    safe_target = _safe_name(result["target"])
    timestamp = result["created_at"].replace(":", "").replace(" ", "_").replace("-", "")
    base_name = f"host_{safe_target}_{timestamp}"

    summary = result["summary"]
    dns_result = result["dns"]
    availability = result["availability"]
    diagnosis = result["diagnosis"]

    markdown_text = "\n".join(
        [
            f"# 单主机诊断报告 - {result['object_label']}",
            "",
            f"- 目标地址: {result['target']}",
            f"- 对象角色: {result.get('object_role', '自动识别')}",
            f"- 扫描时间: {result['created_at']}",
            f"- 主机状态: {availability['label']}",
            f"- 状态说明: {availability['reason']}",
            f"- 平均时延: {summary['avg_ms'] if summary['avg_ms'] is not None else 'N/A'} ms",
            f"- 丢包率: {summary['loss_rate']}%",
            f"- DNS 服务器: {result['dns_server']}",
            f"- DNS 测试域名: {result['dns_domain']}",
            f"- DNS 状态: {'成功' if dns_result['ok'] else '失败'}",
            f"- DNS 响应时间: {dns_result['response_ms']} ms",
            f"- DNS 结果: {', '.join(dns_result['answers']) if dns_result['answers'] else '无'}",
            "",
            "## 诊断结论",
            "",
            diagnosis["summary"],
            "",
            "## 关键信号",
            "",
            "| Signal | Status | Detail |",
            "| --- | --- | --- |",
        ]
        + [
            f"| {item['signal']} | {item['status']} | {item['detail']} |"
            for item in diagnosis["signal_table"]
        ]
        + [
            "",
            "## 关键发现",
            "",
        ]
        + [f"- {item}" for item in diagnosis["findings"]]
        + [
            "",
            "## 建议动作",
            "",
        ]
        + [f"- {item}" for item in diagnosis["recommendations"]]
        + [
            "",
            "## 端口结果",
            "",
            "| Port | Protocol | State | Service | Product | Version | Extra |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
        + [
            f"| {item['port']} | {item['protocol']} | {item['state']} | {item['service'] or ''} | {item['product'] or ''} | {item['version'] or ''} | {item['extrainfo'] or ''} |"
            for item in result["ports"]
        ]
        + [
            "",
            "## 路由追踪",
            "",
            "| TTL | IP | RTT(ms) | Host |",
            "| --- | --- | --- | --- |",
        ]
        + [
            f"| {item['ttl']} | {item['ip'] or ''} | {item['rtt'] if item['rtt'] is not None else ''} | {item['host'] or ''} |"
            for item in result["hops"]
        ]
        + [
            "",
            "## 告警与提示",
            "",
            f"- 错误: {'; '.join(result['errors']) if result['errors'] else '无'}",
            f"- 提示: {'; '.join(result['warnings']) if result['warnings'] else '无'}",
        ]
    )

    csv_rows = [
        {
            "label": result["object_label"],
            "target": result["target"],
            "role": result.get("object_role", "自动识别"),
            "scan_time": result["created_at"],
            "availability": availability["label"],
            "availability_reason": availability["reason"],
            "avg_ms": summary["avg_ms"],
            "loss_rate": summary["loss_rate"],
            "dns_ok": dns_result["ok"],
            "dns_response_ms": dns_result["response_ms"],
            "diagnosis_summary": diagnosis["summary"],
            "port": item["port"],
            "protocol": item["protocol"],
            "state": item["state"],
            "service": item["service"],
            "product": item["product"],
            "version": item["version"],
            "extrainfo": item["extrainfo"],
        }
        for item in result["ports"]
    ]
    if not csv_rows:
        csv_rows = [
            {
                "label": result["object_label"],
                "target": result["target"],
                "role": result.get("object_role", "自动识别"),
                "scan_time": result["created_at"],
                "availability": availability["label"],
                "availability_reason": availability["reason"],
                "avg_ms": summary["avg_ms"],
                "loss_rate": summary["loss_rate"],
                "dns_ok": dns_result["ok"],
                "dns_response_ms": dns_result["response_ms"],
                "diagnosis_summary": diagnosis["summary"],
                "port": None,
                "protocol": None,
                "state": None,
                "service": None,
                "product": None,
                "version": None,
                "extrainfo": None,
            }
        ]
    csv_text = _to_csv_text(csv_rows)
    return {
        **_bundle_metadata(base_name, result["created_at"]),
        "markdown_text": markdown_text,
        "csv_text": csv_text,
    }


def build_batch_report_bundle(result: dict[str, Any], report_dir: Path) -> dict[str, str]:
    timestamp = result["created_at"].replace(":", "").replace(" ", "_").replace("-", "")
    base_name = f"batch_{timestamp}"

    markdown_lines = [
        "# 批量巡检报告",
        "",
        f"- 扫描时间: {result['created_at']}",
        f"- 总目标数: {result['summary']['total']}",
        f"- 在线: {result['summary']['online']}",
        f"- 服务在线: {result['summary']['service_reachable']}",
        f"- 路径可达: {result['summary']['route_reachable']}",
        f"- 离线: {result['summary']['unreachable']}",
        "",
        "## 汇总结果",
        "",
        "| Label | Target | Role | Status | Avg(ms) | Loss(%) | Open Ports | Diagnosis |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]

    csv_rows: list[dict[str, Any]] = []
    for item in result["results"]:
        summary = item["summary"]
        diagnosis = item["diagnosis"]
        row = {
            "label": item["object_label"],
            "target": item["target"],
            "role": item.get("object_role", "自动识别"),
            "status": item["availability"]["label"],
            "avg_ms": summary["avg_ms"],
            "loss_rate": summary["loss_rate"],
            "open_port_count": diagnosis["open_port_count"],
            "dns_ok": item["dns"]["ok"],
            "diagnosis_summary": diagnosis["summary"],
        }
        csv_rows.append(row)
        markdown_lines.append(
            f"| {row['label']} | {row['target']} | {row['role']} | {row['status']} | "
            f"{row['avg_ms'] if row['avg_ms'] is not None else 'N/A'} | {row['loss_rate']} | "
            f"{row['open_port_count']} | {row['diagnosis_summary']} |"
        )

    csv_text = _to_csv_text(csv_rows) if csv_rows else ""
    markdown_text = "\n".join(markdown_lines)

    return {
        **_bundle_metadata(base_name, result["created_at"]),
        "markdown_text": markdown_text,
        "csv_text": csv_text,
    }


def build_lan_report_bundle(result: dict[str, Any], report_dir: Path) -> dict[str, str]:
    safe_target = _safe_name(result["cidr"])
    timestamp = result["created_at"].replace(":", "").replace(" ", "_").replace("-", "")
    base_name = f"lan_{safe_target}_{timestamp}"

    markdown_text = "\n".join(
        [
            f"# 局域网扫描报告 - {result['cidr']}",
            "",
            f"- 扫描时间: {result['created_at']}",
            f"- 发现设备数: {len(result['devices'])}",
            f"- 错误: {'; '.join(result['errors']) if result['errors'] else '无'}",
            f"- 提示: {'; '.join(result['warnings']) if result['warnings'] else '无'}",
            "",
            "## 在线设备",
            "",
            "| IP | MAC | Hostname |",
            "| --- | --- | --- |",
        ]
        + [
            f"| {item['ip']} | {item['mac']} | {item['hostname'] or ''} |"
            for item in result["devices"]
        ]
    )

    csv_rows = [
        {
            "cidr": result["cidr"],
            "scan_time": result["created_at"],
            "ip": item["ip"],
            "mac": item["mac"],
            "hostname": item["hostname"],
        }
        for item in result["devices"]
    ]
    if not csv_rows:
        csv_rows = [
            {
                "cidr": result["cidr"],
                "scan_time": result["created_at"],
                "ip": None,
                "mac": None,
                "hostname": None,
            }
        ]
    csv_text = _to_csv_text(csv_rows)
    return {
        **_bundle_metadata(base_name, result["created_at"]),
        "markdown_text": markdown_text,
        "csv_text": csv_text,
    }
