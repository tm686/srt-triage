"""
Lead scoring engine — evaluates parsed nmap results against lead_signals.json,
produces ranked host list.
"""

import fnmatch
import json
import re
from pathlib import Path

from lib import db as db_mod


def load_signals(config_dir: str = "config") -> list[dict]:
    signals_path = Path(config_dir) / "lead_signals.json"
    with open(signals_path) as f:
        data = json.load(f)
    return data["signals"]


def score_host(host_data: dict, signals: list[dict]) -> tuple[int, list[dict]]:
    """
    Score a single host against all signals.

    host_data: parsed nmap host dict with 'ports' list, each port having
               'service', 'product', 'scripts' etc.

    Returns (total_score, breakdown) where breakdown is a list of
    {"signal": label, "score": int, "match_detail": str}
    """
    total = 0
    breakdown = []
    matched_labels = set()  # deduplicate

    for signal in signals:
        stype = signal["type"]
        match_val = signal["match"]
        score = signal["score"]
        label = signal["label"]

        hits = _evaluate_signal(stype, match_val, host_data)
        for detail in hits:
            key = f"{label}:{detail}"
            if key not in matched_labels:
                matched_labels.add(key)
                total += score
                breakdown.append({
                    "signal": label,
                    "score": score,
                    "match_detail": detail,
                })

    # Sort breakdown by score descending
    breakdown.sort(key=lambda x: x["score"], reverse=True)
    return total, breakdown


def _evaluate_signal(stype: str, match_val, host_data: dict) -> list[str]:
    """Return list of match detail strings if signal matches."""
    hits = []
    ports = host_data.get("ports", [])

    if stype == "nse_script":
        # Check port-level scripts
        for p in ports:
            for script in p.get("scripts", []):
                if fnmatch.fnmatch(script["id"], match_val):
                    hits.append(f"port {p['port']}: {script['id']}")
        # Check host-level scripts
        for script in host_data.get("host_scripts", []):
            if fnmatch.fnmatch(script["id"], match_val):
                hits.append(f"host: {script['id']}")

    elif stype == "service":
        for p in ports:
            svc = p.get("service", "")
            if svc == match_val or svc.startswith(match_val + "/"):
                hits.append(f"port {p['port']}: {svc}")

    elif stype == "port":
        target_port = int(match_val)
        for p in ports:
            if p["port"] == target_port and p.get("state", "") == "open":
                hits.append(f"port {target_port} open")

    elif stype == "product_regex":
        pattern = re.compile(match_val, re.IGNORECASE)
        for p in ports:
            product_str = p.get("product", "")
            version_str = p.get("version", "")
            full = f"{product_str} {version_str}".strip()
            if product_str and pattern.search(full):
                hits.append(f"port {p['port']}: {full}")

    return hits


def score_hosts(parsed_hosts: list[dict], conn, config_dir: str = "config"):
    """
    Score all parsed hosts and store results in db.
    Returns list of (ip, total_score, breakdown) sorted by score desc.
    """
    signals = load_signals(config_dir)
    results = []

    for host in parsed_hosts:
        ip = host["ip"]
        total, breakdown = score_host(host, signals)

        # Find host_id from db
        row = conn.execute("SELECT id FROM hosts WHERE ip = ?", (ip,)).fetchone()
        if row:
            db_mod.save_score(conn, row["id"], total, breakdown)

        results.append((ip, total, breakdown))

    results.sort(key=lambda x: x[1], reverse=True)
    return results


def rescore_all(conn, config_dir: str = "config"):
    """Re-score all hosts from stored port/script data."""
    signals = load_signals(config_dir)
    hosts = conn.execute("SELECT id, ip FROM hosts").fetchall()

    for host_row in hosts:
        host_id = host_row["id"]
        ip = host_row["ip"]

        # Rebuild host_data from db
        host_data = _build_host_data_from_db(conn, host_id, ip)
        total, breakdown = score_host(host_data, signals)
        db_mod.save_score(conn, host_id, total, breakdown)


def _build_host_data_from_db(conn, host_id: int, ip: str) -> dict:
    """Reconstruct a host_data dict from database records."""
    ports = conn.execute(
        "SELECT * FROM ports WHERE host_id = ? ORDER BY port", (host_id,)
    ).fetchall()

    port_list = []
    for p in ports:
        scripts = conn.execute(
            "SELECT script_id as id, output FROM scripts WHERE port_id = ?",
            (p["id"],)
        ).fetchall()
        port_list.append({
            "port": p["port"],
            "protocol": p["protocol"],
            "state": p["state"],
            "service": p["service"],
            "product": p["product"],
            "version": p["version"],
            "extra_info": p["extra_info"],
            "scripts": [dict(s) for s in scripts],
        })

    host_scripts = conn.execute(
        "SELECT script_id as id, output FROM host_scripts WHERE host_id = ?",
        (host_id,)
    ).fetchall()

    return {
        "ip": ip,
        "ports": port_list,
        "host_scripts": [dict(s) for s in host_scripts],
    }
