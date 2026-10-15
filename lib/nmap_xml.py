"""
nmap XML parser — uses xml.etree.ElementTree to extract hosts, ports,
services, and NSE script output from nmap -oX output.
"""

import xml.etree.ElementTree as ET
from pathlib import Path


def parse_nmap_xml(xml_path: str) -> list[dict]:
    """
    Parse an nmap XML output file.

    Returns list of host dicts:
    [
        {
            "ip": "10.0.0.5",
            "hostname": "host.example.com",
            "status": "up",
            "ports": [
                {
                    "port": 22,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "ssh",
                    "product": "OpenSSH",
                    "version": "8.9",
                    "extra_info": "Ubuntu Linux; protocol 2.0",
                    "scripts": [
                        {"id": "ssh-hostkey", "output": "..."}
                    ]
                }
            ],
            "host_scripts": [
                {"id": "smb-os-discovery", "output": "..."}
            ]
        }
    ]
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()
    hosts = []

    for host_elem in root.findall("host"):
        # Status
        status_elem = host_elem.find("status")
        status = status_elem.get("state", "unknown") if status_elem is not None else "unknown"
        if status != "up":
            continue

        # IP address
        ip = ""
        hostname = ""
        for addr in host_elem.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr", "")
                break
        if not ip:
            continue

        # Hostname
        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            hn = hostnames_elem.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "")

        # Ports
        ports = []
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                state_elem = port_elem.find("state")
                state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"

                service_elem = port_elem.find("service")
                service = ""
                product = ""
                version = ""
                extra_info = ""
                if service_elem is not None:
                    service = service_elem.get("name", "")
                    product = service_elem.get("product", "")
                    version = service_elem.get("version", "")
                    extra_info = service_elem.get("extrainfo", "")

                # Per-port scripts
                scripts = []
                for script_elem in port_elem.findall("script"):
                    scripts.append({
                        "id": script_elem.get("id", ""),
                        "output": script_elem.get("output", "")
                    })

                ports.append({
                    "port": int(port_elem.get("portid", 0)),
                    "protocol": port_elem.get("protocol", "tcp"),
                    "state": state,
                    "service": service,
                    "product": product,
                    "version": version,
                    "extra_info": extra_info,
                    "scripts": scripts,
                })

        # Host-level scripts
        host_scripts = []
        hostscript_elem = host_elem.find("hostscript")
        if hostscript_elem is not None:
            for script_elem in hostscript_elem.findall("script"):
                host_scripts.append({
                    "id": script_elem.get("id", ""),
                    "output": script_elem.get("output", "")
                })

        hosts.append({
            "ip": ip,
            "hostname": hostname,
            "status": status,
            "ports": ports,
            "host_scripts": host_scripts,
        })

    return hosts
