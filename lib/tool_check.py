"""
Tool availability checker — ported from srt-recon, plain dicts.
"""

import json
import shutil
from pathlib import Path

TOOLS = ["nmap", "rustscan", "httpx", "searchsploit", "ffuf"]


def check_tools(config_dir: str = "config") -> dict[str, dict]:
    """
    Check availability of required tools.
    Returns: {"tool_name": {"available": bool, "path": str|None}}
    """
    # Load paths.json for bin_dir
    paths_file = Path(config_dir) / "paths.json"
    extra_paths = []
    if paths_file.exists():
        with open(paths_file) as f:
            paths_cfg = json.load(f)
        bin_dir = paths_cfg.get("bin_dir")
        if bin_dir:
            extra_paths.append(bin_dir)

    results = {}
    for name in TOOLS:
        path = None
        # Check extra_paths first
        for ep in extra_paths:
            candidate = Path(ep) / name
            if candidate.is_file():
                path = str(candidate)
                break
        if not path:
            path = shutil.which(name)
        results[name] = {"available": path is not None, "path": path}
    return results


def check_required(config_dir: str = "config") -> tuple[bool, dict[str, dict]]:
    """Check that minimum required tools (nmap, rustscan) are available."""
    tools = check_tools(config_dir)
    required = ["nmap", "rustscan"]
    all_ok = all(tools[t]["available"] for t in required)
    return all_ok, tools
