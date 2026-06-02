CREATE TABLE IF NOT EXISTS scan_task (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    note TEXT
);

CREATE TABLE IF NOT EXISTS host_result (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER NOT NULL,
    target TEXT NOT NULL,
    is_up INTEGER NOT NULL,
    sent INTEGER NOT NULL,
    received INTEGER NOT NULL,
    avg_ms REAL,
    min_ms REAL,
    max_ms REAL,
    loss_rate REAL NOT NULL,
    dns_server TEXT,
    dns_domain TEXT,
    dns_ok INTEGER NOT NULL,
    dns_ms REAL,
    dns_answers TEXT,
    errors_json TEXT,
    warnings_json TEXT,
    FOREIGN KEY(task_id) REFERENCES scan_task(id)
);

CREATE TABLE IF NOT EXISTS port_result (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_result_id INTEGER NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT,
    state TEXT,
    service TEXT,
    product TEXT,
    version TEXT,
    extrainfo TEXT,
    FOREIGN KEY(host_result_id) REFERENCES host_result(id)
);

CREATE TABLE IF NOT EXISTS hop_result (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_result_id INTEGER NOT NULL,
    ttl INTEGER NOT NULL,
    ip TEXT,
    rtt REAL,
    host TEXT,
    FOREIGN KEY(host_result_id) REFERENCES host_result(id)
);

CREATE TABLE IF NOT EXISTS device_result (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER NOT NULL,
    ip TEXT NOT NULL,
    mac TEXT,
    hostname TEXT,
    FOREIGN KEY(task_id) REFERENCES scan_task(id)
);
