from __future__ import annotations
#SQlite 数据库访问层，负责扫描结果的存储和查询
#写入任务表、主机结果、端口结果、路由结果
import json
import sqlite3
from pathlib import Path
from typing import Any


SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    return connection


def init_db(db_path: Path) -> None:
    schema = SCHEMA_PATH.read_text(encoding="utf-8")
    with _connect(db_path) as connection:
        connection.executescript(schema)
        connection.commit()


def save_host_scan(db_path: Path, result: dict[str, Any]) -> int:
    summary = result["summary"]
    dns_result = result["dns"]
    errors = result["errors"]
    warnings = result["warnings"]
    status = "ok" if not errors else "partial"
    note = "; ".join(errors[:3]) if errors else result["diagnosis"]["summary"]

    with _connect(db_path) as connection:
        cursor = connection.cursor()
        cursor.execute(
            """
            INSERT INTO scan_task (target, scan_type, status, created_at, note)
            VALUES (?, ?, ?, ?, ?)
            """,
            (result["target"], "host_diagnostic", status, result["created_at"], note),
        )
        task_id = cursor.lastrowid

        cursor.execute(
            """
            INSERT INTO host_result (
                task_id, target, is_up, sent, received, avg_ms, min_ms, max_ms,
                loss_rate, dns_server, dns_domain, dns_ok, dns_ms, dns_answers,
                errors_json, warnings_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                task_id,
                result["target"],
                int(summary["is_up"]),
                summary["sent"],
                summary["received"],
                summary["avg_ms"],
                summary["min_ms"],
                summary["max_ms"],
                summary["loss_rate"],
                result["dns_server"],
                result["dns_domain"],
                int(dns_result["ok"]),
                dns_result["response_ms"],
                json.dumps(dns_result["answers"], ensure_ascii=False),
                json.dumps(errors, ensure_ascii=False),
                json.dumps(warnings, ensure_ascii=False),
            ),
        )
        host_result_id = cursor.lastrowid

        cursor.executemany(
            """
            INSERT INTO port_result (
                host_result_id, port, protocol, state, service, product, version, extrainfo
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    host_result_id,
                    item["port"],
                    item["protocol"],
                    item["state"],
                    item["service"],
                    item["product"],
                    item["version"],
                    item["extrainfo"],
                )
                for item in result["ports"]
            ],
        )

        cursor.executemany(
            """
            INSERT INTO hop_result (host_result_id, ttl, ip, rtt, host)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                (
                    host_result_id,
                    item["ttl"],
                    item["ip"],
                    item["rtt"],
                    item["host"],
                )
                for item in result["hops"]
            ],
        )
        connection.commit()
    return task_id


def save_lan_scan(db_path: Path, result: dict[str, Any]) -> int:
    errors = result["errors"]
    status = "ok" if not errors else "partial"
    note = "; ".join(errors[:3]) if errors else f'{len(result["devices"])} devices discovered'

    with _connect(db_path) as connection:
        cursor = connection.cursor()
        cursor.execute(
            """
            INSERT INTO scan_task (target, scan_type, status, created_at, note)
            VALUES (?, ?, ?, ?, ?)
            """,
            (result["cidr"], "lan_discovery", status, result["created_at"], note),
        )
        task_id = cursor.lastrowid

        cursor.executemany(
            """
            INSERT INTO device_result (task_id, ip, mac, hostname)
            VALUES (?, ?, ?, ?)
            """,
            [
                (task_id, item["ip"], item["mac"], item["hostname"])
                for item in result["devices"]
            ],
        )
        connection.commit()
    return task_id


def list_recent_tasks(db_path: Path, limit: int = 20) -> list[dict[str, Any]]:
    with _connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT id, target, scan_type, status, created_at, note
            FROM scan_task
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_task_detail(db_path: Path, task_id: int) -> dict[str, Any]:
    with _connect(db_path) as connection:
        task_row = connection.execute(
            "SELECT * FROM scan_task WHERE id = ?",
            (task_id,),
        ).fetchone()

        if task_row is None:
            raise ValueError(f"未找到 task_id={task_id} 的扫描记录。")

        task = dict(task_row)
        if task["scan_type"] == "host_diagnostic":
            host_row = connection.execute(
                "SELECT * FROM host_result WHERE task_id = ?",
                (task_id,),
            ).fetchone()
            ports = connection.execute(
                """
                SELECT port, protocol, state, service, product, version, extrainfo
                FROM port_result
                WHERE host_result_id = ?
                ORDER BY port ASC
                """,
                (host_row["id"],),
            ).fetchall()
            hops = connection.execute(
                """
                SELECT ttl, ip, rtt, host
                FROM hop_result
                WHERE host_result_id = ?
                ORDER BY ttl ASC
                """,
                (host_row["id"],),
            ).fetchall()

            host_result = dict(host_row)
            host_result["dns_answers"] = json.loads(host_result["dns_answers"] or "[]")
            host_result["errors_json"] = json.loads(host_result["errors_json"] or "[]")
            host_result["warnings_json"] = json.loads(host_result["warnings_json"] or "[]")

            return {
                **task,
                "host_result": host_result,
                "ports": [dict(row) for row in ports],
                "hops": [dict(row) for row in hops],
                "devices": [],
            }

        device_rows = connection.execute(
            """
            SELECT ip, mac, hostname
            FROM device_result
            WHERE task_id = ?
            ORDER BY ip ASC
            """,
            (task_id,),
        ).fetchall()
        return {
            **task,
            "host_result": None,
            "ports": [],
            "hops": [],
            "devices": [dict(row) for row in device_rows],
        }
