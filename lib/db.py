"""
SQLite storage for srt-triage — hosts, ports, services, scripts, scores, triage state.
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE NOT NULL,
    hostname TEXT DEFAULT '',
    tier INTEGER DEFAULT 1,
    status TEXT DEFAULT 'pending',
    triage TEXT DEFAULT 'unreviewed',
    notes TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    port INTEGER NOT NULL,
    protocol TEXT DEFAULT 'tcp',
    state TEXT DEFAULT 'open',
    service TEXT DEFAULT '',
    product TEXT DEFAULT '',
    version TEXT DEFAULT '',
    extra_info TEXT DEFAULT '',
    UNIQUE(host_id, port, protocol)
);

CREATE TABLE IF NOT EXISTS scripts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    port_id INTEGER NOT NULL REFERENCES ports(id),
    script_id TEXT NOT NULL,
    output TEXT DEFAULT '',
    UNIQUE(port_id, script_id)
);

CREATE TABLE IF NOT EXISTS host_scripts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    script_id TEXT NOT NULL,
    output TEXT DEFAULT '',
    UNIQUE(host_id, script_id)
);

CREATE TABLE IF NOT EXISTS scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    total_score INTEGER DEFAULT 0,
    breakdown_json TEXT DEFAULT '[]',
    scored_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tier INTEGER NOT NULL,
    target_spec TEXT NOT NULL,
    started_at TEXT DEFAULT (datetime('now')),
    finished_at TEXT,
    status TEXT DEFAULT 'running'
);

CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id);
CREATE INDEX IF NOT EXISTS idx_scripts_port ON scripts(port_id);
CREATE INDEX IF NOT EXISTS idx_scores_host ON scores(host_id);
"""


def init_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


def upsert_host(conn: sqlite3.Connection, ip: str, hostname: str = "",
                tier: int = 1) -> int:
    cur = conn.execute(
        "INSERT INTO hosts (ip, hostname, tier) VALUES (?, ?, ?) "
        "ON CONFLICT(ip) DO UPDATE SET hostname=COALESCE(NULLIF(excluded.hostname,''), hostname), "
        "tier=MAX(tier, excluded.tier)",
        (ip, hostname, tier)
    )
    conn.commit()
    row = conn.execute("SELECT id FROM hosts WHERE ip = ?", (ip,)).fetchone()
    return row["id"]


def upsert_port(conn: sqlite3.Connection, host_id: int, port: int,
                protocol: str = "tcp", state: str = "open",
                service: str = "", product: str = "", version: str = "",
                extra_info: str = "") -> int:
    conn.execute(
        "INSERT INTO ports (host_id, port, protocol, state, service, product, version, extra_info) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(host_id, port, protocol) DO UPDATE SET "
        "state=excluded.state, service=excluded.service, product=excluded.product, "
        "version=excluded.version, extra_info=excluded.extra_info",
        (host_id, port, protocol, state, service, product, version, extra_info)
    )
    conn.commit()
    row = conn.execute(
        "SELECT id FROM ports WHERE host_id=? AND port=? AND protocol=?",
        (host_id, port, protocol)
    ).fetchone()
    return row["id"]


def upsert_script(conn: sqlite3.Connection, port_id: int,
                  script_id: str, output: str = "") -> int:
    conn.execute(
        "INSERT INTO scripts (port_id, script_id, output) VALUES (?, ?, ?) "
        "ON CONFLICT(port_id, script_id) DO UPDATE SET output=excluded.output",
        (port_id, script_id, output)
    )
    conn.commit()
    row = conn.execute(
        "SELECT id FROM scripts WHERE port_id=? AND script_id=?",
        (port_id, script_id)
    ).fetchone()
    return row["id"]


def upsert_host_script(conn: sqlite3.Connection, host_id: int,
                       script_id: str, output: str = "") -> int:
    conn.execute(
        "INSERT INTO host_scripts (host_id, script_id, output) VALUES (?, ?, ?) "
        "ON CONFLICT(host_id, script_id) DO UPDATE SET output=excluded.output",
        (host_id, script_id, output)
    )
    conn.commit()
    row = conn.execute(
        "SELECT id FROM host_scripts WHERE host_id=? AND script_id=?",
        (host_id, script_id)
    ).fetchone()
    return row["id"]


def save_score(conn: sqlite3.Connection, host_id: int, total_score: int,
               breakdown: list[dict]):
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO scores (host_id, total_score, breakdown_json, scored_at) "
        "VALUES (?, ?, ?, ?)",
        (host_id, total_score, json.dumps(breakdown), now)
    )
    conn.commit()


def get_hosts_ranked(conn: sqlite3.Connection) -> list[dict]:
    """Get all hosts with their latest score, ordered by score descending."""
    rows = conn.execute("""
        SELECT h.id, h.ip, h.hostname, h.tier, h.status, h.triage, h.notes,
               COALESCE(s.total_score, 0) as score,
               s.breakdown_json
        FROM hosts h
        LEFT JOIN (
            SELECT host_id, total_score, breakdown_json,
                   ROW_NUMBER() OVER (PARTITION BY host_id ORDER BY scored_at DESC) as rn
            FROM scores
        ) s ON s.host_id = h.id AND s.rn = 1
        ORDER BY COALESCE(s.total_score, 0) DESC
    """).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["breakdown"] = json.loads(d.pop("breakdown_json") or "[]")
        result.append(d)
    return result


def set_triage(conn: sqlite3.Connection, host_id: int, triage: str):
    conn.execute("UPDATE hosts SET triage = ? WHERE id = ?", (triage, host_id))
    conn.commit()


def set_notes(conn: sqlite3.Connection, host_id: int, notes: str):
    conn.execute("UPDATE hosts SET notes = ? WHERE id = ?", (notes, host_id))
    conn.commit()


def promote_host(conn: sqlite3.Connection, host_id: int):
    conn.execute(
        "UPDATE hosts SET triage = 'promoted', tier = 2 WHERE id = ?",
        (host_id,)
    )
    conn.commit()


def set_host_status(conn: sqlite3.Connection, host_id: int, status: str):
    conn.execute("UPDATE hosts SET status = ? WHERE id = ?", (status, host_id))
    conn.commit()


def get_host_detail(conn: sqlite3.Connection, host_id: int) -> dict | None:
    host = conn.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
    if not host:
        return None
    d = dict(host)

    ports = conn.execute(
        "SELECT * FROM ports WHERE host_id = ? ORDER BY port", (host_id,)
    ).fetchall()
    d["ports"] = []
    for p in ports:
        pd = dict(p)
        scripts = conn.execute(
            "SELECT script_id, output FROM scripts WHERE port_id = ?", (p["id"],)
        ).fetchall()
        pd["scripts"] = [dict(s) for s in scripts]
        d["ports"].append(pd)

    host_scripts = conn.execute(
        "SELECT script_id, output FROM host_scripts WHERE host_id = ?", (host_id,)
    ).fetchall()
    d["host_scripts"] = [dict(s) for s in host_scripts]

    scores = conn.execute(
        "SELECT total_score, breakdown_json, scored_at FROM scores "
        "WHERE host_id = ? ORDER BY scored_at DESC LIMIT 1", (host_id,)
    ).fetchone()
    if scores:
        d["score"] = scores["total_score"]
        d["breakdown"] = json.loads(scores["breakdown_json"] or "[]")
    else:
        d["score"] = 0
        d["breakdown"] = []

    return d


def get_promoted_hosts(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT id, ip FROM hosts WHERE triage = 'promoted' AND status != 'scanning'"
    ).fetchall()
    return [dict(r) for r in rows]


def record_scan_start(conn: sqlite3.Connection, tier: int, target_spec: str) -> int:
    cur = conn.execute(
        "INSERT INTO scans (tier, target_spec) VALUES (?, ?)",
        (tier, target_spec)
    )
    conn.commit()
    return cur.lastrowid


def record_scan_end(conn: sqlite3.Connection, scan_id: int, status: str = "completed"):
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "UPDATE scans SET finished_at = ?, status = ? WHERE id = ?",
        (now, status, scan_id)
    )
    conn.commit()
