"""
LeakIX OSINT data fetching module.

Queries the LeakIX host API for passive leak and service intelligence.
No active scanning — all data comes from LeakIX's pre-indexed database.

Expected /host/{ip} JSON structure (list of events):
[
  {
    "event_type": "service" | "leak",
    "port": "80",
    "transport": "tcp",
    "protocol": "http",
    "summary": "Git configuration file exposed",
    "leak": {
      "stage": "open",
      "type": "GitConfig",
      "severity": "high"
    },
    "service": {
      "software": { "name": "nginx", "version": "1.18.0" }
    },
    "tags": ["git"]
  }
]
An empty list means no events found (not an error).
"""

from typing import Any

import requests

_BASE_URL = "https://leakix.net"
_TIMEOUT = 15


def fetch_leakix(api_key: str, ip: str) -> dict[str, Any]:
    """
    Query LeakIX for a given IP and return structured leak and service data.

    Args:
        api_key: LeakIX API key (from leakix.net account).
        ip:      IPv4 address to look up.

    Returns:
        Dict with keys: ip, org, country, services (list of port dicts).
        Returns empty dict if no events are found for the host.

    Raises:
        ValueError:   On authentication failure (401/403).
        RuntimeError: On rate-limit (429), timeout, or other HTTP errors.
    """
    headers = {
        "api-key": api_key,
        "Accept": "application/json",
    }

    try:
        response = requests.get(
            f"{_BASE_URL}/host/{ip}",
            headers=headers,
            timeout=_TIMEOUT,
        )
    except requests.Timeout:
        raise RuntimeError(f"LeakIX: timeout dopo {_TIMEOUT}s")
    except requests.ConnectionError as exc:
        raise RuntimeError(f"LeakIX: errore di connessione — {exc}") from exc

    if response.status_code in (401, 403):
        raise ValueError("LeakIX: API key non valida (401/403)")
    if response.status_code == 404:
        return {}
    if response.status_code == 429:
        raise RuntimeError("LeakIX: rate limit raggiunto (429)")
    if response.status_code != 200:
        raise RuntimeError(f"LeakIX: errore HTTP {response.status_code}")

    raw = response.json()
    if not isinstance(raw, list):
        return {}
    events: list[dict] = raw
    if not events:
        return {}

    # Group events by port number; one entry per port, leaks accumulated
    ports_map: dict[int, dict[str, Any]] = {}

    for event in events:
        port_str: str = str(event.get("port", "0"))
        port_int = int(port_str) if port_str.isdigit() else 0
        if port_int == 0:
            continue

        transport: str = event.get("transport", "tcp").lower()

        if port_int not in ports_map:
            software: dict = event.get("service", {}).get("software", {})
            raw_summary: str = event.get("summary", "").strip()
            ports_map[port_int] = {
                "port": port_int,
                "transport": transport,
                "service": event.get("protocol", ""),
                "product": software.get("name", ""),
                "version": software.get("version", ""),
                "banner": raw_summary[:300] if raw_summary else "",
                "vulns": [],
                "leaks": [],
            }

        if event.get("event_type") == "leak":
            leak_info: dict = event.get("leak", {})
            leak_type = leak_info.get("type", "")
            severity = leak_info.get("severity", "").upper()
            summary = event.get("summary", "")
            label = f"[{severity}] {leak_type}: {summary}".strip(": ") if leak_type else summary
            if label and label not in ports_map[port_int]["leaks"]:
                ports_map[port_int]["leaks"].append(label)

    services = list(ports_map.values())
    if not services:
        return {}

    return {
        "ip": ip,
        "org": "",
        "country": "",
        "services": services,
    }
