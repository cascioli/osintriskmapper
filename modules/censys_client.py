"""
Censys OSINT data fetching module.

Queries the Censys v2 hosts API for passive reconnaissance data.
No active scanning — all data comes from Censys's pre-indexed database.

Expected /v2/hosts/{ip} JSON structure:
{
  "code": 200,
  "status": "OK",
  "result": {
    "ip": "1.2.3.4",
    "autonomous_system": {
      "name": "GOOGLE",
      "country_code": "US"
    },
    "services": [
      {
        "port": 443,
        "transport_protocol": "TCP",
        "service_name": "HTTPS",
        "extended_service_name": "HTTPS",
        "banner": "..."
      }
    ]
  }
}
"""

from typing import Any

import requests

_BASE_URL = "https://search.censys.io/api"
_TIMEOUT = 15


def fetch_censys(api_id: str, api_secret: str, ip: str) -> dict[str, Any]:
    """
    Query Censys v2 for a given IP and return structured service data.

    Args:
        api_id:     Censys API ID (from search.censys.io/account/api).
        api_secret: Censys API Secret.
        ip:         IPv4 address to look up.

    Returns:
        Dict with keys: ip, org, country, services (list of port dicts).
        Returns empty dict if the host has no indexed data.

    Raises:
        ValueError:   On authentication failure (401/403).
        RuntimeError: On rate-limit (429), timeout, or other HTTP errors.
    """
    try:
        response = requests.get(
            f"{_BASE_URL}/v2/hosts/{ip}",
            auth=(api_id, api_secret),
            timeout=_TIMEOUT,
        )
    except requests.Timeout:
        raise RuntimeError(f"Censys: timeout dopo {_TIMEOUT}s")
    except requests.ConnectionError as exc:
        raise RuntimeError(f"Censys: errore di connessione — {exc}") from exc

    if response.status_code in (401, 403):
        raise ValueError("Censys: credenziali non valide (401/403)")
    if response.status_code == 404:
        return {}
    if response.status_code == 429:
        raise RuntimeError("Censys: rate limit raggiunto (429)")
    if response.status_code != 200:
        raise RuntimeError(f"Censys: errore HTTP {response.status_code}")

    payload = response.json()
    result: dict = payload.get("result", {})
    if not result:
        return {}

    as_info: dict = result.get("autonomous_system", {})
    org: str = as_info.get("name", "")
    country: str = as_info.get("country_code", "")

    raw_services: list[dict] = result.get("services", [])
    services: list[dict[str, Any]] = []

    for svc in raw_services:
        raw_banner: str = svc.get("banner", "").strip()
        services.append(
            {
                "port": int(svc.get("port", 0)),
                "transport": svc.get("transport_protocol", "TCP").lower(),
                "service": svc.get("service_name", "").lower(),
                "product": svc.get("extended_service_name", ""),
                "version": "",
                "banner": raw_banner[:300] if raw_banner else "",
                "vulns": [],
                "leaks": [],
            }
        )

    return {
        "ip": result.get("ip", ip),
        "org": org,
        "country": country,
        "services": services,
    }
