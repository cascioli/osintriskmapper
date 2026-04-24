"""
ZoomEye OSINT data fetching module.

Queries the ZoomEye host search API for passive reconnaissance data.
No active scanning — all data comes from ZoomEye's pre-indexed database.

Expected /host/search JSON structure:
{
  "available": int,
  "matches": [
    {
      "ip": "1.2.3.4",
      "portinfo": {
        "port": 80,
        "service": "http",
        "app": "Apache httpd",   # product name
        "version": "2.4.41",
        "banner": "HTTP/1.1 200 OK\\r\\n..."
      },
      "geoinfo": {
        "country": {"names": {"en": "United States"}},
        "organization": "Google LLC"
      }
    }
  ]
}
"""

from typing import Any

import requests

_BASE_URL = "https://api.zoomeye.org"
_TIMEOUT = 15


def fetch_zoomeye(api_key: str, ip: str) -> dict[str, Any]:
    """
    Query ZoomEye for a given IP and return structured service data.

    Args:
        api_key: ZoomEye API key (from zoomeye.org account page).
        ip:      IPv4 address to look up.

    Returns:
        Dict with keys: ip, org, country, services (list of port dicts).
        Returns empty dict if the host has no indexed data.

    Raises:
        ValueError:   On authentication failure (401).
        RuntimeError: On rate-limit (429), timeout, or other HTTP errors.
    """
    headers = {"API-KEY": api_key}
    params = {"query": f"ip:{ip}", "page": 1}

    try:
        response = requests.get(
            f"{_BASE_URL}/host/search",
            headers=headers,
            params=params,
            timeout=_TIMEOUT,
        )
    except requests.Timeout:
        raise RuntimeError(f"ZoomEye: timeout dopo {_TIMEOUT}s")
    except requests.ConnectionError as exc:
        raise RuntimeError(f"ZoomEye: errore di connessione — {exc}") from exc

    if response.status_code == 401:
        raise ValueError("ZoomEye: API key non valida (401)")
    if response.status_code == 403:
        raise ValueError(
            "ZoomEye: accesso negato (403) — il piano gratuito "
            "potrebbe non includere l'accesso API a /host/search"
        )
    if response.status_code == 404:
        return {}
    if response.status_code == 429:
        raise RuntimeError("ZoomEye: rate limit raggiunto (429)")
    if response.status_code != 200:
        raise RuntimeError(f"ZoomEye: errore HTTP {response.status_code}")

    payload = response.json()
    matches: list[dict] = payload.get("matches", [])
    if not matches:
        return {}

    services: list[dict[str, Any]] = []
    org = ""
    country = ""

    for match in matches:
        portinfo: dict = match.get("portinfo", {})
        geoinfo: dict = match.get("geoinfo", {})

        if not org:
            org = geoinfo.get("organization", "")
        if not country:
            country_obj = geoinfo.get("country", {})
            country = country_obj.get("names", {}).get("en", "")

        raw_banner: str = portinfo.get("banner", "").strip()
        services.append(
            {
                "port": int(portinfo.get("port", 0)),
                "transport": "tcp",
                "service": portinfo.get("service", ""),
                "product": portinfo.get("app", ""),
                "version": portinfo.get("version", ""),
                "banner": raw_banner[:300] if raw_banner else "",
                "vulns": [],
                "leaks": [],
            }
        )

    return {
        "ip": ip,
        "org": org,
        "country": country,
        "services": services,
    }
