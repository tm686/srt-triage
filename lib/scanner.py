"""
Scan orchestration — rustscan sweep, nmap -sC -sV -oX, subprocess management.
"""

import json
import logging
import os
import re
import subprocess
import tempfile
from pathlib import Path

from lib import db as db_mod
from lib.nmap_xml import parse_nmap_xml
from lib.scorer import score_hosts

logger = logging.getLogger(__name__)


def _load_curated_ports(config_dir: str) -> str:
    """Load curated port list from ports.json, return as comma-separated string."""
    ports_file = Path(config_dir) / "ports.json"
    with open(ports_file) as f:
        data = json.load(f)
    return ",".join(str(p["port"]) for p in data["ports"])


def _load_tiers(config_dir: str) -> dict:
    tiers_file = Path(config_dir) / "tiers.json"
    with open(tiers_file) as f:
        return json.load(f)


def _run_rustscan(targets: list[str], ports: str, config: dict,
                  status_cb=None) -> dict[str, list[int]]:
    """
    Run rustscan on targets with given ports.
    Returns dict mapping IP -> list of open ports.
    """
    tiers = config.get("tiers", {})
    tier1 = tiers.get("tier1", {})
    batch_size = tier1.get("rustscan_batch_size", 1000)
    ulimit = tier1.get("rustscan_ulimit", 5000)

    cmd = [
        "rustscan",
        "-a", ",".join(targets),
        "-p", ports,
        "--ulimit", str(ulimit),
        "-b", str(batch_size),
        "-g",  # greppable output
    ]

    if status_cb:
        status_cb(f"Running rustscan on {len(targets)} target(s)...")

    logger.info("Running: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=tier1.get("timeout", 600)
        )
    except subprocess.TimeoutExpired:
        logger.error("Rustscan timed out")
        if status_cb:
            status_cb("Rustscan timed out!")
        return {}
    except FileNotFoundError:
        logger.error("rustscan not found")
        if status_cb:
            status_cb("ERROR: rustscan not found in PATH")
        return {}

    # Parse greppable output: "10.0.0.5 -> [22,80,443]"
    host_ports = {}
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or "->" not in line:
            continue
        match = re.match(r"^([\d.]+)\s*->\s*\[(.+)\]", line)
        if match:
            ip = match.group(1)
            port_list = [int(p.strip()) for p in match.group(2).split(",") if p.strip().isdigit()]
            if port_list:
                host_ports[ip] = port_list

    if status_cb:
        total_ports = sum(len(v) for v in host_ports.values())
        status_cb(f"Rustscan done: {len(host_ports)} hosts, {total_ports} open ports")

    return host_ports


def _run_nmap(ip: str, ports: list[int], nmap_flags: list[str],
              config: dict, status_cb=None, timeout: int = 600) -> str | None:
    """
    Run nmap on a single host with XML output.
    Returns path to XML output file, or None on failure.
    """
    xml_fd, xml_path = tempfile.mkstemp(suffix=".xml", prefix=f"nmap_{ip}_")
    os.close(xml_fd)

    port_str = ",".join(str(p) for p in ports)
    cmd = ["nmap"] + list(nmap_flags) + ["-oX", xml_path, "-p", port_str, ip]

    if status_cb:
        status_cb(f"nmap scanning {ip} ({len(ports)} ports)...")

    logger.info("Running: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        if result.returncode != 0:
            logger.warning("nmap returned %d for %s: %s", result.returncode, ip, result.stderr)
    except subprocess.TimeoutExpired:
        logger.error("nmap timed out for %s", ip)
        if status_cb:
            status_cb(f"nmap timed out for {ip}")
        return None
    except FileNotFoundError:
        logger.error("nmap not found")
        return None

    if Path(xml_path).exists() and Path(xml_path).stat().st_size > 0:
        return xml_path

    return None


def _store_parsed_hosts(conn, parsed_hosts: list[dict], tier: int = 1):
    """Store parsed nmap results into the database."""
    for host in parsed_hosts:
        ip = host["ip"]
        hostname = host.get("hostname", "")
        host_id = db_mod.upsert_host(conn, ip, hostname, tier)
        db_mod.set_host_status(conn, host_id, "scanned")

        for port_data in host.get("ports", []):
            port_id = db_mod.upsert_port(
                conn, host_id,
                port=port_data["port"],
                protocol=port_data.get("protocol", "tcp"),
                state=port_data.get("state", "open"),
                service=port_data.get("service", ""),
                product=port_data.get("product", ""),
                version=port_data.get("version", ""),
                extra_info=port_data.get("extra_info", ""),
            )
            for script in port_data.get("scripts", []):
                db_mod.upsert_script(conn, port_id, script["id"], script.get("output", ""))

        for script in host.get("host_scripts", []):
            db_mod.upsert_host_script(conn, host_id, script["id"], script.get("output", ""))


def run_tier1(targets: list[str], conn, config: dict, status_cb=None):
    """
    Tier 1 scan: rustscan curated ports -> nmap -sC -sV -oX on open ports.
    """
    config_dir = config.get("config_dir", "config")
    tiers = _load_tiers(config_dir)
    curated_ports = _load_curated_ports(config_dir)

    scan_id = db_mod.record_scan_start(conn, 1, ",".join(targets))

    # Create host records as pending
    for t in targets:
        db_mod.upsert_host(conn, t, tier=1)
        db_mod.set_host_status(conn,
            conn.execute("SELECT id FROM hosts WHERE ip=?", (t,)).fetchone()["id"],
            "pending"
        )

    # Step 1: rustscan sweep
    host_ports = _run_rustscan(targets, curated_ports, config, status_cb)

    if not host_ports:
        if status_cb:
            status_cb("No open ports found by rustscan")
        db_mod.record_scan_end(conn, scan_id, "completed")
        return

    # Step 2: nmap each host
    nmap_flags = tiers["tier1"].get("nmap_flags", ["-sC", "-sV", "--open"])
    timeout = tiers["tier1"].get("timeout", 600)
    all_parsed = []

    for i, (ip, ports) in enumerate(host_ports.items()):
        if status_cb:
            status_cb(f"nmap {i+1}/{len(host_ports)}: {ip}")

        host_id = conn.execute("SELECT id FROM hosts WHERE ip=?", (ip,)).fetchone()["id"]
        db_mod.set_host_status(conn, host_id, "scanning")

        xml_path = _run_nmap(ip, ports, nmap_flags, config, status_cb, timeout)
        if xml_path:
            parsed = parse_nmap_xml(xml_path)
            _store_parsed_hosts(conn, parsed, tier=1)
            all_parsed.extend(parsed)
            # Clean up temp file
            try:
                os.unlink(xml_path)
            except OSError:
                pass

        db_mod.set_host_status(conn, host_id, "scanned")

    # Step 3: score all hosts
    if status_cb:
        status_cb("Scoring hosts...")
    if all_parsed:
        score_hosts(all_parsed, conn, config_dir)

    db_mod.record_scan_end(conn, scan_id, "completed")
    if status_cb:
        status_cb(f"Tier 1 complete: {len(all_parsed)} hosts scanned")


def run_tier2(host_ip: str, conn, config: dict, status_cb=None):
    """
    Tier 2 scan: nmap -p- -sC -sV -oX on a single promoted host.
    """
    config_dir = config.get("config_dir", "config")
    tiers = _load_tiers(config_dir)

    host_row = conn.execute("SELECT id FROM hosts WHERE ip=?", (host_ip,)).fetchone()
    if not host_row:
        logger.error("Host %s not found in db", host_ip)
        return
    host_id = host_row["id"]

    scan_id = db_mod.record_scan_start(conn, 2, host_ip)
    db_mod.set_host_status(conn, host_id, "scanning")

    if status_cb:
        status_cb(f"Tier 2 full scan: {host_ip}")

    nmap_flags = tiers["tier2"].get("nmap_flags", ["-p-", "-sC", "-sV", "--open"])
    timeout = tiers["tier2"].get("timeout", 1800)

    # Full port scan — pass all 65535 ports via -p-
    # -p- is already in nmap_flags, so we pass a dummy port list
    # Actually, we need to handle -p- specially
    xml_fd, xml_path = tempfile.mkstemp(suffix=".xml", prefix=f"nmap_t2_{host_ip}_")
    os.close(xml_fd)

    cmd = ["nmap"] + list(nmap_flags) + ["-oX", xml_path, host_ip]

    logger.info("Tier 2 running: %s", " ".join(cmd))

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        logger.error("Tier 2 nmap timed out for %s", host_ip)
        db_mod.set_host_status(conn, host_id, "scanned")
        db_mod.record_scan_end(conn, scan_id, "timeout")
        if status_cb:
            status_cb(f"Tier 2 timed out for {host_ip}")
        return
    except FileNotFoundError:
        logger.error("nmap not found")
        db_mod.record_scan_end(conn, scan_id, "error")
        return

    if Path(xml_path).exists() and Path(xml_path).stat().st_size > 0:
        parsed = parse_nmap_xml(xml_path)
        _store_parsed_hosts(conn, parsed, tier=2)
        if parsed:
            score_hosts(parsed, conn, config_dir)
        try:
            os.unlink(xml_path)
        except OSError:
            pass

    db_mod.set_host_status(conn, host_id, "scanned")
    db_mod.record_scan_end(conn, scan_id, "completed")
    if status_cb:
        status_cb(f"Tier 2 complete for {host_ip}")
