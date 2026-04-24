"""
LLM analysis module.
Supports Google Gemini (google-generativeai) and any OpenAI-compatible endpoint
(OpenAI, Anthropic via proxy, Ollama, etc.).
"""

import json
from typing import Any


SYSTEM_PROMPT = (
    "Sei un analista SOC. Analizza questi dati OSINT aggregati e deduplicati. "
    "Scrivi un report esecutivo sui rischi principali e assegna un livello di rischio "
    "complessivo. Sii conciso."
)

# Keys to strip from merged host before sending to the LLM to reduce token usage
_EXCLUDED_KEYS: frozenset[str] = frozenset({"sources_queried"})


def _build_prompt(data: dict[str, Any]) -> str:
    """Serialize merged host data to JSON, excluding redundant fields."""
    payload = {k: v for k, v in data.items() if k not in _EXCLUDED_KEYS}
    # Convert ports from dict[int, entry] to list for cleaner LLM JSON
    if "ports" in payload and isinstance(payload["ports"], dict):
        payload["ports"] = list(payload["ports"].values())
    return json.dumps(payload, indent=2, ensure_ascii=False)


def analyze_with_gemini(
    api_key: str,
    model_name: str,
    data: dict[str, Any],
) -> str:
    """
    Send host data to Google Gemini and return the generated risk report.

    Args:
        api_key:    Google AI Studio API key.
        model_name: Gemini model ID (e.g. 'gemini-2.5-flash').
        data:       Merged host dict from merger.merge_sources.

    Returns:
        Report text produced by the model.

    Raises:
        Exception: Propagates google.api_core errors with a descriptive message.
    """
    try:
        import google.generativeai as genai  # lazy import — optional dependency
    except ImportError as exc:
        raise ImportError(
            "Pacchetto 'google-generativeai' non installato. "
            "Esegui: pip install google-generativeai"
        ) from exc

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(
        model_name=model_name,
        system_instruction=SYSTEM_PROMPT,
    )

    response = model.generate_content(_build_prompt(data))
    return response.text


def analyze_with_openai_compat(
    api_key: str,
    base_url: str,
    model: str,
    data: dict[str, Any],
) -> str:
    """
    Send host data to any OpenAI-compatible chat endpoint and return the risk report.

    Compatible with: OpenAI, Anthropic (via proxy), Ollama (http://localhost:11434/v1).

    Args:
        api_key:  Provider API key (or 'ollama' for local Ollama).
        base_url: Root URL of the API, e.g. 'https://api.openai.com/v1'.
        model:    Model identifier, e.g. 'gpt-4o-mini' or 'llama3.2'.
        data:     Merged host dict from merger.merge_sources.

    Returns:
        Report text produced by the model.

    Raises:
        openai.APIError: On authentication failure, rate-limit, or API error.
    """
    try:
        from openai import OpenAI  # lazy import — optional dependency
    except ImportError as exc:
        raise ImportError(
            "Pacchetto 'openai' non installato. Esegui: pip install openai"
        ) from exc

    client = OpenAI(api_key=api_key, base_url=base_url)

    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": _build_prompt(data)},
        ],
        max_tokens=1024,
    )
    return response.choices[0].message.content
