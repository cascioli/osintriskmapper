"""
LLM analysis module for host/network OSINT data.

Supports Google Gemini (google-genai SDK) and any OpenAI-compatible endpoint
(OpenAI, Anthropic via proxy, Ollama, etc.).
"""

import json
from typing import Any

from google import genai
from google.genai import types as genai_types
from openai import OpenAI


SYSTEM_PROMPT = (
    "Sei un analista SOC. Analizza questi dati OSINT aggregati e deduplicati "
    "relativi all'infrastruttura di rete di un host. "
    "Scrivi un report esecutivo sui rischi principali (porte esposte, servizi vulnerabili, "
    "leak rilevati) e assegna un livello di rischio complessivo (Basso/Medio/Alto/Critico). "
    "Sii conciso e non inventare dati."
)

_EXCLUDED_KEYS: frozenset[str] = frozenset({"sources_queried"})


def _build_prompt(data: dict[str, Any]) -> str:
    """Serialize merged host data to JSON, excluding redundant fields."""
    payload = {k: v for k, v in data.items() if k not in _EXCLUDED_KEYS}
    if "ports" in payload and isinstance(payload["ports"], dict):
        payload["ports"] = list(payload["ports"].values())
    return json.dumps(payload, indent=2, ensure_ascii=False)


def analyze_with_gemini(
    api_key: str,
    model_name: str,
    data: dict[str, Any],
) -> str:
    """Send host data to Google Gemini and return the generated risk report.

    Args:
        api_key:    Google AI Studio API key.
        model_name: Gemini model ID (e.g. 'gemini-2.5-flash').
        data:       Merged host dict from merger.merge_sources.

    Returns:
        Report text produced by the model.

    Raises:
        RuntimeError: On API call failures.
    """
    try:
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model=model_name,
            contents=_build_prompt(data),
            config=genai_types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=0.3,
            ),
        )
        return response.text or ""
    except Exception as exc:
        raise RuntimeError(f"Gemini API error (host report): {exc}") from exc


def analyze_with_openai_compat(
    api_key: str,
    base_url: str,
    model: str,
    data: dict[str, Any],
) -> str:
    """Send host data to any OpenAI-compatible chat endpoint and return the risk report.

    Compatible with: OpenAI, Anthropic (via proxy), Ollama (http://localhost:11434/v1).

    Args:
        api_key:  Provider API key (or 'ollama' for local Ollama).
        base_url: Root URL of the API, e.g. 'https://api.openai.com/v1'.
        model:    Model identifier, e.g. 'gpt-4o-mini' or 'llama3.2'.
        data:     Merged host dict from merger.merge_sources.

    Returns:
        Report text produced by the model.

    Raises:
        RuntimeError: On API call failures.
    """
    try:
        client = OpenAI(api_key=api_key, base_url=base_url)
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": _build_prompt(data)},
            ],
            max_tokens=1024,
        )
        return response.choices[0].message.content or ""
    except Exception as exc:
        raise RuntimeError(f"OpenAI-compat API error (host report): {exc}") from exc
