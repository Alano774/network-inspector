from __future__ import annotations

import csv
import io
from typing import Any


ENTERPRISE_PRESETS = {
    "公共服务演示": [
        "公共DNS-114,114.114.114.114,DNS服务器,114.114.114.114,www.baidu.com",
        "阿里公共DNS,223.5.5.5,DNS服务器,223.5.5.5,www.taobao.com",
        "百度首页,www.baidu.com,Web站点,114.114.114.114,www.baidu.com",
        "腾讯首页,www.qq.com,Web站点,119.29.29.29,www.qq.com",
    ],
    "总部办公网络巡检": [
        "# 更贴近 IT 技术支持/桌面运维场景，实验环境地址",
        "总部办公网关,192.168.10.1,网关/路由器,114.114.114.114,www.baidu.com",
        "总部核心交换机,192.168.10.2,交换机/AP,114.114.114.114,www.baidu.com",
        "总部无线控制器,192.168.10.3,交换机/AP,114.114.114.114,www.baidu.com",
        "OA办公入口,192.168.10.20,Web站点,114.114.114.114,www.baidu.com",
        "文件共享服务器,192.168.10.30,NAS/文件服务器,114.114.114.114,www.baidu.com",
        "前台打印机,192.168.10.40,打印机,114.114.114.114,www.baidu.com",
        "会议室终端,192.168.10.50,办公终端,114.114.114.114,www.baidu.com",
    ],
    "服务器区巡检": [
        "# 适合展示业务系统、数据库、中间件等核心资产的网络可达性",
        "DMZ负载均衡,172.16.1.1,网关/路由器,114.114.114.114,www.baidu.com",
        "门户Web服务器,172.16.1.10,Web站点,114.114.114.114,www.baidu.com",
        "应用服务器-01,172.16.1.20,数据库/应用服务器,114.114.114.114,www.baidu.com",
        "应用服务器-02,172.16.1.21,数据库/应用服务器,114.114.114.114,www.baidu.com",
        "数据库主库,172.16.1.30,数据库/应用服务器,114.114.114.114,www.baidu.com",
        "数据库备库,172.16.1.31,数据库/应用服务器,114.114.114.114,www.baidu.com",
        "备份存储,172.16.1.40,NAS/文件服务器,114.114.114.114,www.baidu.com",
    ],
    "分支机构网络巡检": [
        "# 适合展示多办公点/门店/校区的网络巡检能力",
        "深圳分部网关,10.10.1.1,网关/路由器,114.114.114.114,www.baidu.com",
        "深圳分部交换机,10.10.1.2,交换机/AP,114.114.114.114,www.baidu.com",
        "深圳分部NAS,10.10.1.20,NAS/文件服务器,114.114.114.114,www.baidu.com",
        "深圳分部打印机,10.10.1.30,打印机,114.114.114.114,www.baidu.com",
        "上海分部网关,10.20.1.1,网关/路由器,114.114.114.114,www.baidu.com",
        "上海分部交换机,10.20.1.2,交换机/AP,114.114.114.114,www.baidu.com",
        "上海分部打印机,10.20.1.30,打印机,114.114.114.114,www.baidu.com",
    ],
    "校园实验室网络巡检": [
        "# 适合学生项目展示，兼顾实验室终端、打印机和共享存储",
        "实验室网关,10.20.0.1,网关/路由器,114.114.114.114,www.baidu.com",
        "实验室交换机,10.20.0.2,交换机/AP,114.114.114.114,www.baidu.com",
        "教师机,10.20.0.10,办公终端,114.114.114.114,www.baidu.com",
        "学生机房终端,10.20.0.20,办公终端,114.114.114.114,www.baidu.com",
        "实验室打印机,10.20.0.30,打印机,114.114.114.114,www.baidu.com",
        "实验室NAS,10.20.0.40,NAS/文件服务器,114.114.114.114,www.baidu.com",
    ],
}


def get_preset_names() -> list[str]:
    return list(ENTERPRISE_PRESETS.keys())


def get_preset_text(name: str) -> str:
    return "\n".join(ENTERPRISE_PRESETS.get(name, []))


def parse_batch_targets(
    raw_text: str,
    default_dns_server: str,
    default_dns_domain: str,
    default_role: str = "自动识别",
) -> tuple[list[dict[str, Any]], list[str]]:
    items: list[dict[str, Any]] = []
    errors: list[str] = []

    for line_no, raw_line in enumerate(raw_text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        try:
            row = next(csv.reader(io.StringIO(stripped)))
        except Exception as exc:
            errors.append(f"第 {line_no} 行无法解析：{exc}")
            continue

        columns = [part.strip() for part in row]
        if not columns or not columns[0]:
            continue

        label = ""
        target = ""
        role = default_role
        dns_server = default_dns_server
        dns_domain = default_dns_domain

        if len(columns) == 1:
            target = columns[0]
            label = target
        elif len(columns) == 2:
            label, target = columns[:2]
        elif len(columns) == 3:
            label, target, role = columns[:3]
        elif len(columns) == 4:
            label, target, role, dns_server = columns[:4]
        else:
            label, target, role, dns_server, dns_domain = columns[:5]

        if not target:
            errors.append(f"第 {line_no} 行缺少目标地址。")
            continue

        items.append(
            {
                "label": label or target,
                "target": target,
                "object_role": role or default_role,
                "dns_server": dns_server or default_dns_server,
                "dns_domain": dns_domain or default_dns_domain,
            }
        )

    return items, errors
