"""Leak-Lookup API client — checks email addresses against known breach databases."""

import time
import requests


LEAKLOOKUP_BASE_URL = "https://leak-lookup.com/api/search"
# Leak-Lookup free tier is rate-limited; 1.5 s between requests keeps us safe.
_REQUEST_DELAY_SECONDS: float = 1.5


def check_emails_for_breaches(
    emails: list[str],
    api_key: str,
) -> dict[str, list[str]]:
    """Query Leak-Lookup for each email and aggregate breach source names.

    Args:
        emails: List of email addresses to check.
        api_key: Leak-Lookup API key.

    Returns:
        A dict mapping each email to a list of breach source names.
        Emails with no breaches map to an empty list.
        Example: {"user@example.com": ["LinkedIn", "Adobe"], "other@example.com": []}

    Raises:
        ValueError: When the API key is rejected (401/403).
    """
    results: dict[str, list[str]] = {}

    for index, email in enumerate(emails):
        # Respect rate limit — skip delay only before the very first request.
        if index > 0:
            time.sleep(_REQUEST_DELAY_SECONDS)

        breaches = _query_single_email(email, api_key)
        results[email] = breaches

    return results


def _query_single_email(email: str, api_key: str) -> list[str]:
    """Return breach source names for a single email address.

    Returns an empty list when the email is clean or the request fails
    non-fatally (rate limit exceeded, server error).

    Raises:
        ValueError: On authentication failure.
    """
    payload: dict[str, str] = {
        "key": api_key,
        "type": "email_address",
        "query": email,
    }

    try:
        response = requests.post(LEAKLOOKUP_BASE_URL, data=payload, timeout=15)
    except requests.exceptions.RequestException:
        # Non-fatal: network hiccup; treat this email as unchecked (empty).
        return []

    if response.status_code in (401, 403):
        raise ValueError("Leak-Lookup: API key non valida o non autorizzata.")

    if response.status_code == 429:
        # Hard rate-limit hit: wait and return empty rather than crashing.
        time.sleep(5.0)
        return []

    if response.status_code != 200:
        return []

    data: dict = response.json()

    # Successful response: {"success": true, "message": {"SourceName": [...], ...}}
    if not data.get("success"):
        return []

    message = data.get("message", {})
    if not isinstance(message, dict):
        return []

    # Keys are breach/source names; each value is a list of leaked records.
    return list(message.keys())
