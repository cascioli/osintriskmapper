"""
Data normalization and deduplication module.

Merges structured data from ZoomEye, Censys, and LeakIX into a single
unified host representation. Deduplication key: port number.
"""

from typing import Any

import pandas as pd


def merge_sources(
    zoomeye: dict[str, Any],
    censys: dict[str, Any],
    leakix: dict[str, Any],
    target_ip: str,
    sources_queried: list[str],
) -> dict[str, Any]:
    """
    Merge and deduplicate OSINT data from three sources into a unified host dict.

    Port deduplication:
    - Key = port number (int).
    - First non-empty value wins for service/product/version/banner.
    - vulns and leaks are unioned without duplicates.
    - sources list accumulates all source names that reported the port.

    Args:
        zoomeye:         Output of zoomeye_client.fetch_zoomeye (or {}).
        censys:          Output of censys_client.fetch_censys (or {}).
        leakix:          Output of leakix_client.fetch_leakix (or {}).
        target_ip:       Original target IP string.
        sources_queried: Names of sources that were queried (including failed ones).

    Returns:
        MergedHost dict with keys:
          ip, org, country,
          ports (dict[int, PortEntry]),
          host_vulns, host_leaks,
          sources_queried, sources_ok
    """
    merged: dict[str, Any] = {
        "ip": target_ip,
        "org": "",
        "country": "",
        "ports": {},
        "host_vulns": [],
        "host_leaks": [],
        "sources_queried": sources_queried,
        "sources_ok": [],
    }

    source_map: dict[str, dict[str, Any]] = {
        "ZoomEye": zoomeye,
        "Censys": censys,
        "LeakIX": leakix,
    }

    for source_name, source_data in source_map.items():
        if not source_data:
            continue

        merged["sources_ok"].append(source_name)

        if not merged["org"]:
            merged["org"] = source_data.get("org", "") or ""
        if not merged["country"]:
            merged["country"] = source_data.get("country", "") or ""

        for svc in source_data.get("services", []):
            port_key = int(svc.get("port", 0))
            if port_key == 0:
                continue

            if port_key not in merged["ports"]:
                merged["ports"][port_key] = {
                    "port": port_key,
                    "transport": svc.get("transport", "tcp") or "tcp",
                    "service": svc.get("service", ""),
                    "product": svc.get("product", ""),
                    "version": svc.get("version", ""),
                    "banner": svc.get("banner", ""),
                    "vulns": list(svc.get("vulns", [])),
                    "leaks": list(svc.get("leaks", [])),
                    "sources": [source_name],
                }
            else:
                entry = merged["ports"][port_key]
                if source_name not in entry["sources"]:
                    entry["sources"].append(source_name)
                if not entry["service"] and svc.get("service"):
                    entry["service"] = svc["service"]
                if not entry["product"] and svc.get("product"):
                    entry["product"] = svc["product"]
                if not entry["version"] and svc.get("version"):
                    entry["version"] = svc["version"]
                if not entry["banner"] and svc.get("banner"):
                    entry["banner"] = svc["banner"]
                for v in svc.get("vulns", []):
                    if v not in entry["vulns"]:
                        entry["vulns"].append(v)
                for lk in svc.get("leaks", []):
                    if lk not in entry["leaks"]:
                        entry["leaks"].append(lk)

    return merged


def to_dataframe(merged: dict[str, Any]) -> pd.DataFrame:
    """
    Convert a MergedHost dict to a Pandas DataFrame for Streamlit display.

    Columns: Porta | Servizio | Dettagli/Banner | Vulnerabilità (CVE/Leak) | Fonti

    Args:
        merged: Output of merge_sources.

    Returns:
        DataFrame sorted by port number ascending. Empty DataFrame if no ports.
    """
    columns = ["Porta", "Servizio", "Dettagli/Banner", "Vulnerabilità (CVE/Leak)", "Fonti"]

    if not merged["ports"]:
        return pd.DataFrame(columns=columns)

    rows = []
    for port_int, entry in sorted(merged["ports"].items()):
        # Build "service (product version)" label
        svc = entry.get("service", "")
        product = entry.get("product", "")
        version = entry.get("version", "")
        if product and version:
            detail = f"{product} {version}"
        elif product:
            detail = product
        else:
            detail = ""
        service_label = f"{svc} ({detail})".strip("() ") if detail else svc

        banner = entry.get("banner", "")
        banner_display = (banner[:150] + "…") if len(banner) > 150 else banner

        all_issues = entry.get("vulns", []) + entry.get("leaks", [])
        issues_str = "; ".join(all_issues) if all_issues else "—"

        rows.append(
            {
                "Porta": f"{port_int}/{entry.get('transport', 'tcp')}",
                "Servizio": service_label.strip(),
                "Dettagli/Banner": banner_display,
                "Vulnerabilità (CVE/Leak)": issues_str,
                "Fonti": ", ".join(entry.get("sources", [])),
            }
        )

    return pd.DataFrame(rows)
