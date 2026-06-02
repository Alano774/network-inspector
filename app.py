from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

from db import repo
from services.diagnosis_rules import ENTERPRISE_ROLES
from services.diagnostic_service import (
    hydrate_host_result_from_detail,
    run_batch_diagnostic,
    run_host_diagnostic,
    run_lan_discovery,
)
from services.report_service import (
    build_batch_report_bundle,
    build_host_report_bundle,
    build_lan_report_bundle,
    save_report_bundle,
)
from services.target_templates import get_preset_names, get_preset_text, parse_batch_targets


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "data" / "network_inspector" / "inspector.db"
REPORT_DIR = BASE_DIR / "reports"
REPORT_RETENTION_DAYS = 30
REPORT_RETENTION_GROUPS = 100


def render_messages(messages: list[str], level: str = "warning") -> None:
    for message in messages:
        if level == "error":
            st.error(message)
        else:
            st.warning(message)


def render_diagnosis_panel(result: dict[str, Any]) -> None:
    availability = result["availability"]
    diagnosis = result["diagnosis"]

    st.subheader("诊断结论")
    if availability["code"] == "online":
        st.success(diagnosis["summary"])
    elif availability["code"] in {"service_reachable", "route_reachable"}:
        st.info(diagnosis["summary"])
    else:
        st.error(diagnosis["summary"])

    col1, col2 = st.columns(2)
    col1.markdown("**状态说明**")
    col1.write(availability["reason"])
    col2.markdown("**对象角色**")
    col2.write(result.get("object_role", "自动识别"))

    st.markdown("**多信号判定**")
    st.dataframe(pd.DataFrame(diagnosis["signal_table"]), width="stretch")

    findings_col, recommendations_col = st.columns(2)
    findings_col.markdown("**关键发现**")
    for item in diagnosis["findings"]:
        findings_col.write(f"- {item}")

    recommendations_col.markdown("**建议动作**")
    for item in diagnosis["recommendations"]:
        recommendations_col.write(f"- {item}")


def render_host_result(result: dict[str, Any]) -> None:
    summary = result["summary"]
    dns_result = result["dns"]
    ports = result["ports"]
    hops = result["hops"]
    diagnosis = result["diagnosis"]
    availability = result["availability"]

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("主机状态", availability["label"])
    col2.metric("平均时延", f'{summary["avg_ms"]} ms' if summary["avg_ms"] is not None else "N/A")
    col3.metric("丢包率", f'{summary["loss_rate"]}%')
    col4.metric("开放端口数", str(diagnosis["open_port_count"]))
    col5.metric("对象角色", result.get("object_role", "自动识别"))

    render_diagnosis_panel(result)

    st.subheader("诊断概览")
    overview = pd.DataFrame(
        [
            {
                "对象名称": result.get("object_label", result["target"]),
                "目标": result["target"],
                "角色": result.get("object_role", "自动识别"),
                "扫描时间": result["created_at"],
                "发送包数": summary["sent"],
                "接收包数": summary["received"],
                "最小时延(ms)": summary["min_ms"],
                "最大时延(ms)": summary["max_ms"],
                "DNS 服务器": result["dns_server"],
                "DNS 目标域名": result["dns_domain"],
                "DNS 状态": "成功" if dns_result["ok"] else "失败",
                "DNS 响应(ms)": dns_result["response_ms"],
                "DNS 结果": ", ".join(dns_result["answers"]) if dns_result["answers"] else "",
            }
        ]
    )
    st.dataframe(overview, width="stretch")

    st.subheader("开放端口与服务识别")
    if ports:
        st.dataframe(pd.DataFrame(ports), width="stretch")
    else:
        st.info("当前未识别到开放端口，或者 Nmap 扫描未返回结果。")

    st.subheader("路由追踪")
    if hops:
        st.dataframe(pd.DataFrame(hops), width="stretch")
    else:
        st.info("当前未获取到 traceroute 结果，可能是目标策略或权限限制导致。")

    st.subheader("原始时延样本")
    if summary["samples"]:
        st.line_chart(pd.DataFrame({"rtt_ms": summary["samples"]}))
    else:
        st.info("没有收到 ICMP 回包。")


def render_batch_result(result: dict[str, Any]) -> None:
    summary = result["summary"]

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("总目标数", str(summary["total"]))
    col2.metric("在线", str(summary["online"]))
    col3.metric("服务在线", str(summary["service_reachable"]))
    col4.metric("离线", str(summary["unreachable"]))

    if result["errors"]:
        render_messages(result["errors"], level="error")

    if not result["results"]:
        st.info("本次批量巡检没有生成有效结果。")
        return

    rows = []
    for item in result["results"]:
        rows.append(
            {
                "对象名称": item["object_label"],
                "目标": item["target"],
                "角色": item.get("object_role", "自动识别"),
                "状态": item["availability"]["label"],
                "平均时延(ms)": item["summary"]["avg_ms"],
                "丢包率(%)": item["summary"]["loss_rate"],
                "开放端口数": item["diagnosis"]["open_port_count"],
                "DNS 状态": "成功" if item["dns"]["ok"] else "失败",
                "诊断结论": item["diagnosis"]["summary"],
            }
        )

    st.subheader("批量巡检汇总")
    st.dataframe(pd.DataFrame(rows), width="stretch")

    options = {
        f'{item["object_label"]} | {item["target"]} | {item["availability"]["label"]}': idx
        for idx, item in enumerate(result["results"])
    }
    selected_label = st.selectbox("查看某个目标的详细诊断", list(options.keys()))
    render_host_result(result["results"][options[selected_label]])


def render_lan_result(result: dict[str, Any]) -> None:
    devices = result["devices"]

    col1, col2, col3 = st.columns(3)
    col1.metric("发现设备数", str(len(devices)))
    col2.metric("网段", result["cidr"])
    col3.metric("扫描时间", result["created_at"])

    st.subheader("在线设备")
    if devices:
        st.dataframe(pd.DataFrame(devices), width="stretch")
    else:
        st.info("未发现在线设备，或者当前网段不可通过 ARP 探测。")


def render_report_downloads(bundle: dict[str, str], prefix: str) -> None:
    st.subheader("巡检报告导出")
    col1, col2 = st.columns(2)
    col1.download_button(
        label="下载 Markdown 报告",
        data=bundle["markdown_text"],
        file_name=f'{bundle["base_name"]}.md',
        mime="text/markdown",
        key=f"{prefix}_md",
    )
    col2.download_button(
        label="下载 CSV 报告",
        data=bundle["csv_text"],
        file_name=f'{bundle["base_name"]}.csv',
        mime="text/csv",
        key=f"{prefix}_csv",
    )
    st.caption("下载按钮直接基于内存中的报告内容，不会自动写入 `reports/` 目录。")

    save_state_key = f"{prefix}_saved_paths"
    if st.button("保存 Markdown + CSV 到本地报告目录", key=f"{prefix}_save"):
        st.session_state[save_state_key] = save_report_bundle(
            bundle=bundle,
            report_dir=REPORT_DIR,
            retention_days=REPORT_RETENTION_DAYS,
            retention_groups=REPORT_RETENTION_GROUPS,
        )

    saved_info = st.session_state.get(save_state_key)
    if saved_info:
        st.success(
            "报告已保存到本地目录："
            f'`{saved_info["markdown_path"]}` 和 `{saved_info["csv_path"]}`'
        )
        st.caption(
            f'保存策略：按日期分层到 `reports/{bundle["report_date"]}/`，'
            f'默认保留最近 {saved_info["retention_days"]} 天且最多 {saved_info["retention_groups"]} 份报告。'
        )
        if saved_info["removed_by_age"] or saved_info["removed_by_count"]:
            st.caption(
                "本次清理结果："
                f'按天数移除了 {saved_info["removed_by_age"]} 份，'
                f'按数量移除了 {saved_info["removed_by_count"]} 份。'
            )


def render_history(db_path: Path) -> None:
    tasks = repo.list_recent_tasks(db_path)
    st.subheader("最近扫描记录")
    if not tasks:
        st.info("还没有历史记录，先执行一次扫描吧。")
        return

    task_df = pd.DataFrame(tasks)
    st.dataframe(task_df, width="stretch")

    task_options = {
        f'#{item["id"]} | {item["scan_type"]} | {item["target"]} | {item["created_at"]}': item["id"]
        for item in tasks
    }
    selected_label = st.selectbox("查看扫描详情", list(task_options.keys()))
    detail = repo.get_task_detail(db_path, task_options[selected_label])

    if detail["scan_type"] == "host_diagnostic":
        render_host_result(hydrate_host_result_from_detail(detail))
    else:
        st.markdown("**局域网扫描详情**")
        if detail["devices"]:
            st.dataframe(pd.DataFrame(detail["devices"]), width="stretch")
        else:
            st.info("该次局域网扫描没有发现设备。")


def ensure_session_defaults() -> None:
    if "batch_targets_input" not in st.session_state:
        st.session_state["batch_targets_input"] = get_preset_text("公共服务演示")


def main() -> None:
    st.set_page_config(page_title="企业局域网网络巡检工具", layout="wide")
    repo.init_db(DB_PATH)
    ensure_session_defaults()

    st.title("企业局域网网络巡检与故障诊断工具")
    st.caption("基于 Python + Scapy + Nmap + Streamlit + SQLite 的网络巡检与辅助诊断项目")

    with st.expander("运行前说明", expanded=True):
        st.markdown(
            "\n".join(
                [
                    "- 请仅扫描你自己的实验环境或已经获得授权的目标。",
                    "- `Scapy` 在 Windows 上通常需要先安装 `Npcap` 并以管理员权限运行。",
                    "- `Nmap` 需要提前安装并保证 `nmap -V` 可以在终端执行。",
                    "- `ARP` 扫描仅适用于当前二层局域网网段。跨网段请优先使用主机诊断功能。",
                    "- 在线状态已改为多信号判断：会综合 ICMP、开放端口、DNS 与 traceroute 结果，而不是只看 ping。",
                ]
            )
        )

    host_tab, batch_tab, lan_tab, history_tab = st.tabs(
        ["单主机诊断", "批量巡检", "局域网扫描", "历史记录"]
    )

    with host_tab:
        with st.form("host_diagnostic_form"):
            col1, col2 = st.columns(2)
            target = col1.text_input("目标 IP 或域名", value="www.baidu.com")
            dns_server = col2.text_input("DNS 服务器", value="114.114.114.114")
            col3, col4 = st.columns(2)
            object_label = col3.text_input("对象名称", value="百度首页")
            object_role = col4.selectbox("对象角色", ENTERPRISE_ROLES, index=4)
            col5, col6, col7 = st.columns(3)
            dns_domain = col5.text_input("DNS 测试域名", value="www.baidu.com")
            ping_count = col6.number_input("Ping 次数", min_value=1, max_value=10, value=4, step=1)
            top_ports = col7.slider("Nmap 扫描端口数", min_value=10, max_value=200, value=30, step=10)
            submitted = st.form_submit_button("执行单主机诊断", width="stretch")

        if submitted:
            with st.spinner("正在执行主机诊断，请稍候..."):
                host_result = run_host_diagnostic(
                    target=target.strip(),
                    dns_server=dns_server.strip(),
                    dns_domain=dns_domain.strip(),
                    ping_count=int(ping_count),
                    top_ports=int(top_ports),
                    object_label=object_label.strip() or target.strip(),
                    object_role=object_role,
                )
                repo.save_host_scan(DB_PATH, host_result)
                bundle = build_host_report_bundle(host_result, REPORT_DIR)
                st.session_state["host_result"] = host_result
                st.session_state["host_report_bundle"] = bundle
                st.session_state["host_saved_paths"] = None

        if "host_result" in st.session_state:
            render_messages(st.session_state["host_result"]["warnings"], level="warning")
            render_messages(st.session_state["host_result"]["errors"], level="error")
            render_host_result(st.session_state["host_result"])
            render_report_downloads(st.session_state["host_report_bundle"], prefix="host")

    with batch_tab:
        st.markdown("**企业常见对象模板**")
        preset_col1, preset_col2 = st.columns([3, 1])
        selected_preset = preset_col1.selectbox("载入模板", get_preset_names())
        if preset_col2.button("加载到文本框"):
            st.session_state["batch_targets_input"] = get_preset_text(selected_preset)

        with st.form("batch_diagnostic_form"):
            batch_text = st.text_area(
                "批量目标列表",
                key="batch_targets_input",
                height=220,
                help="每行一个目标，格式：对象名称,目标,对象角色,DNS服务器,DNS测试域名。后两列可省略。",
            )
            col1, col2, col3 = st.columns(3)
            default_dns_server = col1.text_input("默认 DNS 服务器", value="114.114.114.114")
            default_dns_domain = col2.text_input("默认 DNS 测试域名", value="www.baidu.com")
            default_role = col3.selectbox("默认对象角色", ENTERPRISE_ROLES, index=0)
            col4, col5 = st.columns(2)
            batch_ping_count = col4.number_input("批量 Ping 次数", min_value=1, max_value=10, value=3, step=1)
            batch_top_ports = col5.slider("批量 Nmap 扫描端口数", min_value=10, max_value=100, value=20, step=10)
            submitted = st.form_submit_button("执行批量巡检", width="stretch")

        if submitted:
            items, parse_errors = parse_batch_targets(
                batch_text,
                default_dns_server=default_dns_server.strip(),
                default_dns_domain=default_dns_domain.strip(),
                default_role=default_role,
            )
            if not items:
                st.error("未解析到有效的批量目标，请检查输入格式。")
            else:
                with st.spinner("正在执行批量巡检，请稍候..."):
                    batch_result = run_batch_diagnostic(
                        items=items,
                        ping_count=int(batch_ping_count),
                        top_ports=int(batch_top_ports),
                    )
                    for item in batch_result["results"]:
                        repo.save_host_scan(DB_PATH, item)
                    batch_result["errors"] = parse_errors + batch_result["errors"]
                    bundle = build_batch_report_bundle(batch_result, REPORT_DIR)
                    st.session_state["batch_result"] = batch_result
                    st.session_state["batch_report_bundle"] = bundle
                    st.session_state["batch_saved_paths"] = None

        if "batch_result" in st.session_state:
            render_batch_result(st.session_state["batch_result"])
            render_report_downloads(st.session_state["batch_report_bundle"], prefix="batch")

    with lan_tab:
        with st.form("lan_scan_form"):
            col1, col2 = st.columns(2)
            cidr = col1.text_input("局域网网段", value="192.168.1.0/24")
            arp_timeout = col2.slider("ARP 超时时间（秒）", min_value=1, max_value=5, value=2)
            submitted = st.form_submit_button("执行局域网扫描", width="stretch")

        if submitted:
            with st.spinner("正在扫描局域网，请稍候..."):
                lan_result = run_lan_discovery(cidr=cidr.strip(), timeout=int(arp_timeout))
                repo.save_lan_scan(DB_PATH, lan_result)
                bundle = build_lan_report_bundle(lan_result, REPORT_DIR)
                st.session_state["lan_result"] = lan_result
                st.session_state["lan_report_bundle"] = bundle
                st.session_state["lan_saved_paths"] = None

        if "lan_result" in st.session_state:
            render_messages(st.session_state["lan_result"]["warnings"], level="warning")
            render_messages(st.session_state["lan_result"]["errors"], level="error")
            render_lan_result(st.session_state["lan_result"])
            render_report_downloads(st.session_state["lan_report_bundle"], prefix="lan")

    with history_tab:
        render_history(DB_PATH)


if __name__ == "__main__":
    main()
