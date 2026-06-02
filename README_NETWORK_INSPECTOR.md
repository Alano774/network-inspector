# 企业局域网网络巡检与故障诊断工具

这是一个项目骨架，核心覆盖：

- ICMP 连通性、时延、丢包率检测
- Nmap 端口扫描与服务识别
- traceroute 路由跳数分析
- DNS 解析与响应时间检测
- 局域网 ARP 扫描发现在线设备
- SQLite 历史记录存储
- Markdown / CSV 巡检报告导出

## 目录结构

```text
app.py
scanners/
db/
services/
requirements-network-inspector.txt
```

## 安装依赖

```bash
pip install -r requirements-network-inspector.txt
```

系统依赖：

- 安装 `Nmap`，并确保终端执行 `nmap -V` 正常
- Windows 下安装 `Npcap`
- 使用管理员权限运行

## 启动

```bash
streamlit run app.py
```

## 推荐演示流程

1. 先用单主机诊断测试公网 DNS 或内网测试机
2. 再对本地测试网段执行 ARP 扫描
3. 导出 Markdown / CSV 报告
4. 在历史记录页面展示落库结果

## 后续扩展建议

- 接入 `pysnmp` 做交换机 / AP / 打印机状态采集
- 增加 `IP -> 厂商` 识别和网段资产标签
- 增加告警阈值和健康评分
- 接入 GLPI / 企业微信机器人，实现自动工单或告警通知

各个模板的作用是什么？
    app.py 项目总入口、页面渲染、表单处理、报告下载与保存
    icmp_ping.py 用Scapy发ICMP探测包，统计时延和丢包率
    dns_check.py 用Scapy发DNS查询包，测试指定DNS服务器解析能力
    nmap_scan.py 调用Nmap做端口扫描和服务识别 
    trace_route.py 调用Nmaptraceroute获取跳数信息
    arp_scan.py 使用arp协议扫描当前二次局域网在线设备
    diagnostic_service.py 扫描编排层
    diagnosis_rules.py 规则引擎
    targe_templates.py 批量巡检模板
    report_service.py 报告构建与保存策略
    schema.sql+db/repo.py SQLite存储层

为什么使用streamlit?
    首次streamlit是一个用python快速搭建的数据工具/内部工具/可视化web页面；
    由于这个项目的重点在网络诊断逻辑和规则设计，而不是复杂前端开发，所以我用 Streamlit 快速搭建了一个可交互的 Web 界面，把单主机诊断、批量巡检、历史记录和报告导出整合到一个页面里，提升了项目交付效率