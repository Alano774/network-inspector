# 企业局域网网络巡检与故障诊断工具

项目基于 `Python + Streamlit + Scapy + Nmap + SQLite` 实现，支持单主机诊断、批量巡检、局域网设备发现、历史记录存储与报告导出。

## 项目亮点

- 支持 `ICMP`、`DNS`、`端口识别`、`traceroute`、`ARP` 等多种探测方式
- 引入“多信号在线状态判断”，不是只看 `ping`
- 支持批量巡检企业对象，如网关、交换机、打印机、NAS、Web 站点、应用服务器
- 内置规则引擎，自动生成诊断结论与建议动作
- 使用 `SQLite` 保存历史巡检记录
- 支持 `Markdown / CSV` 报告下载，并支持手动保存到本地归档目录

## 适合展示的场景

- 企业办公网络巡检
- 服务器区可达性检测
- 分支机构网络巡检
- 校园实验室网络巡检
- 公网 DNS / Web 服务演示

## 技术栈

### Python 层

- `Streamlit`：快速搭建可交互 Web 页面
- `Scapy`：构造和发送 `ICMP / DNS / ARP` 报文
- `Pandas`：表格数据展示与整理
- `sqlite3`：访问本地 SQLite 数据库

### 系统工具 / 依赖

- `Nmap`：端口扫描、服务识别、路由追踪
- `Npcap`：Windows 下的抓包 / 发包底层依赖
- `SQLite`：轻量级嵌入式数据库

## 核心功能

### 1. 单主机诊断

输入一个目标 IP 或域名后，系统会执行：

- ICMP 连通性检测
- DNS 解析测试
- Nmap 端口扫描与服务识别
- traceroute 路由追踪
- 多信号规则判断

最终输出：

- 主机状态
- 平均时延与丢包率
- 端口与服务信息
- 路由信息
- 自动诊断结论
- 建议动作

### 2. 批量巡检

支持按如下格式批量输入：

```text
对象名称,目标,对象角色,DNS服务器,DNS测试域名
```

例如：

```text
总部办公网关,192.168.10.1,网关/路由器,114.114.114.114,www.baidu.com
文件共享服务器,192.168.10.30,NAS/文件服务器,114.114.114.114,www.baidu.com
前台打印机,192.168.10.40,打印机,114.114.114.114,www.baidu.com
```

项目内置多套企业场景模板：

- `公共服务演示`
- `总部办公网络巡检`
- `服务器区巡检`
- `分支机构网络巡检`
- `校园实验室网络巡检`

### 3. 局域网扫描

使用 ARP 协议扫描当前二层局域网在线设备，输出：

- IP 地址
- MAC 地址
- 主机名（如可解析）

### 4. 历史记录与报告

- 每次扫描结果默认写入 `SQLite`
- 报告默认只在内存中生成，不自动写入 `reports/`
- 用户手动点击后，才会保存 `Markdown + CSV`
- 报告按日期分层保存到 `reports/YYYY-MM-DD/`
- 默认保留最近 `30` 天且最多 `100` 份报告组

## 项目结构

```text
app.py
scanners/
db/
services/
docs/
requirements-network-inspector.txt
```

### 关键模块说明

- `app.py`
  项目总入口，负责页面渲染、表单交互、结果展示、报告下载和手动保存

- `scanners/icmp_ping.py`
  使用 Scapy 发 ICMP 探测包，统计时延与丢包率

- `scanners/dns_check.py`
  使用 Scapy 发 DNS 查询包，验证指定 DNS 服务器解析能力

- `scanners/nmap_scan.py`
  调用 Nmap 做端口扫描与服务识别

- `scanners/trace_route.py`
  调用 Nmap traceroute 获取路由跳数信息

- `scanners/arp_scan.py`
  使用 ARP 协议扫描当前二层局域网在线设备

- `services/diagnostic_service.py`
  扫描编排层，串联多个扫描模块

- `services/diagnosis_rules.py`
  规则引擎，综合 ICMP、端口、DNS、路由等信号输出诊断结论

- `services/target_templates.py`
  批量巡检模板与企业对象示例

- `services/report_service.py`
  报告构建、手动保存和报告清理策略

- `db/schema.sql` + `db/repo.py`
  SQLite 存储层

## 为什么使用 Streamlit

项目重点在：

- 网络诊断逻辑
- 多信号规则设计
- 巡检流程组织
- 报告输出与历史记录

而不是复杂前端开发。  
因此选用 `Streamlit` 快速搭建可交互页面，把更多精力放在网络巡检与诊断逻辑本身。

你可以把它理解为：

> 用 Python 快速做一个可交互的 Web 巡检工具，而不是单纯的命令行脚本。

## 环境要求

- `Python 3.10 - 3.12`
- `Windows 10 / Windows 11`
- 已安装 `Nmap`
- 已安装 `Npcap`
- 建议使用管理员权限运行

## 安装依赖

```bash
pip install -r requirements-network-inspector.txt
```

## 启动方式

```bash
streamlit run app.py
```

## 推荐演示流程

1. 先用 `公共服务演示` 模板做一次批量巡检
2. 再测试 `www.baidu.com` 与 `114.114.114.114` 的诊断差异
3. 演示“多信号状态判断”而不是只看 ping
4. 查看历史记录
5. 下载报告，或手动保存报告到本地目录

## 当前设计上的工程点

- 用规则引擎区分：
  - `在线`
  - `服务在线`
  - `路径可达`
  - `离线`
- 默认只入库，不默认落盘，避免 `reports/` 无限制膨胀
- 批量巡检支持企业对象模板，提升项目真实感

## 后续可扩展方向

- 接入 `SNMP`，采集交换机 / AP / 打印机状态
- 增加定时巡检与时延趋势图
- 增加预期端口 / 对象基线规则
- 接入企业微信 / 邮件 / 工单系统
- 增强资产台账与巡检报告联动

## 项目解析文档

如果你想看更详细的网页版说明，包括：

- 项目背景
- 架构设计
- 模块拆解
- 诊断规则
- 面试复述方式

可以直接打开：

`docs/network-inspector-project-guide.html`

## 说明

本项目仅用于学习、实验和授权环境下的巡检测试。  
请不要对未授权目标执行扫描操作。
