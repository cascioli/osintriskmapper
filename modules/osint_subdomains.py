"""Passive subdomain enumeration via Certificate Transparency (crt.sh)."""

import requests


def get_subdomains(domain: str) -> list[str]:
    """Query crt.sh for subdomains via Certificate Transparency logs.

    Args:
        domain: Target domain (e.g. "example.com").

    Returns:
        Sorted list of unique subdomains (wildcards stripped, deduped).

    Raises:
        RuntimeError: On network failure or unexpected response format.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, timeout=20)
        response.raise_for_status()
    except requests.exceptions.Timeout as exc:
        raise RuntimeError("crt.sh timeout — server lento, riprova.") from exc
    except requests.exceptions.RequestException as exc:
        raise RuntimeError(f"crt.sh request error: {exc}") from exc

    try:
        records: list[dict] = response.json()
    except ValueError as exc:
        raise RuntimeError(f"crt.sh risposta non valida (non-JSON): {exc}") from exc

    seen: set[str] = set()
    for record in records:
        raw = record.get("name_value", "")
        for entry in raw.splitlines():
            entry = entry.strip().lstrip("*").lstrip(".").lower()
            if entry and "." in entry:
                seen.add(entry)

    return sorted(seen)
