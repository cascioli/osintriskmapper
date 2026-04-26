"""Secure credential loading from .env file."""

import os
from dotenv import load_dotenv

load_dotenv()


def get_api_keys() -> dict[str, str]:
    """Load all API keys from environment variables.

    Returns a dict with empty strings for keys not set,
    so callers can safely use .get() or truthiness checks.
    """
    return {
        "HUNTER_API_KEY": os.getenv("HUNTER_API_KEY", ""),
        "LEAKLOOKUP_API_KEY": os.getenv("LEAKLOOKUP_API_KEY", ""),
        "ZOOMEYE_API_KEY": os.getenv("ZOOMEYE_API_KEY", ""),
        "CENSYS_API_ID": os.getenv("CENSYS_API_ID", ""),
        "CENSYS_API_SECRET": os.getenv("CENSYS_API_SECRET", ""),
        "LEAKIX_API_KEY": os.getenv("LEAKIX_API_KEY", ""),
        "GEMINI_API_KEY": os.getenv("GEMINI_API_KEY", ""),
        "OPENAI_API_KEY": os.getenv("OPENAI_API_KEY", ""),
        "GOOGLE_SEARCH_API_KEY": os.getenv("GOOGLE_SEARCH_API_KEY", ""),
        "GOOGLE_CX_ID": os.getenv("GOOGLE_CX_ID", ""),
    }
