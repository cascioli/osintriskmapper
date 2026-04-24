"""
Target resolution utility: domain/URL → IPv4 address.
No active scanning — DNS resolution only.
"""

import ipaddress
import socket
from urllib.parse import urlparse


def _extract_hostname(target: str) -> str:
    """Strip URL scheme, path, port, query — return bare hostname."""
    target = target.strip()
    if "://" in target or target.startswith("//"):
        parsed = urlparse(target if "://" in target else "//" + target)
        return parsed.hostname or target
    return target.split("/")[0].split("?")[0].split("#")[0]


def resolve_target(target: str) -> str:
    """
    Resolve a hostname or URL to an IPv4 address, or validate an existing IP.

    Args:
        target: IPv4 address, domain name, or full URL.

    Returns:
        Resolved IPv4 address string.

    Raises:
        ValueError: If the domain cannot be resolved or input is invalid.
    """
    hostname = _extract_hostname(target)
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror as exc:
        raise ValueError(f"Impossibile risolvere '{hostname}': {exc}") from exc
