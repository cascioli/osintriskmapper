"""AI-powered threat intelligence report generator.

Supports Google Gemini (via google-genai) and OpenAI.
"""

import json
from typing import Literal

from google import genai
from google.genai import types as genai_types
from openai import OpenAI


_SYSTEM_PROMPT = (
    "Sei un analista di Threat Intelligence. "
    "Analizza questi dati relativi alle email aziendali compromesse per questo dominio. "
    "Valuta il rischio di credential stuffing o phishing mirato. "
    "Scrivi un report esecutivo. Non inventare dati. "
    "Nel dataset troverai anche una lista di sottodomini associati al target. "
    "Analizzali e segnala esplicitamente se noti sottodomini che indicano potenziali "
    "ambienti dimenticati, di test o di amministrazione (cerca parole chiave come "
    "test, dev, staging, backup, old, admin, vpn, portal). "
    "Spiega perché rappresentano un rischio per un'azienda. "
    "Il dataset contiene anche un elenco di documenti e file aziendali indicizzati "
    "pubblicamente dai motori di ricerca. Valuta se l'esposizione di questi file "
    "(es. estensioni .sql, .bak, .env o documenti amministrativi) rappresenta un "
    "rischio di Data Leakage e Insecure Direct Object Reference (IDOR). "
    "Fornisci raccomandazioni su come limitare l'indicizzazione."
)

Provider = Literal["gemini", "openai"]


def generate_risk_report(
    data_json: dict,
    provider: Provider,
    model_name: str,
    api_key: str,
    subdomains: list[str] | None = None,
    exposed_documents: list[dict[str, str]] | None = None,
) -> str:
    """Generate an executive risk report from aggregated breach data.

    Args:
        data_json:          Dict mapping email addresses to lists of breach source names.
                            Example: {"user@example.com": ["LinkedIn", "Adobe"]}
        provider:           "gemini" or "openai".
        model_name:         Model identifier (e.g. "gemini-2.5-flash", "gpt-4o-mini").
        api_key:            The relevant provider API key.
        subdomains:         Optional list of subdomains found via Certificate Transparency.
        exposed_documents:  Optional list of dicts with "title" and "url" keys,
                            representing publicly indexed sensitive files found via dorking.

    Returns:
        The raw text of the AI-generated report.

    Raises:
        ValueError: If provider is not recognised.
        RuntimeError: On API call failures.
    """
    subdomain_section = ""
    if subdomains:
        subdomain_section = (
            "\n\nSottodomini rilevati via Certificate Transparency:\n"
            f"```json\n{json.dumps(subdomains, indent=2, ensure_ascii=False)}\n```\n"
        )

    dorking_section = ""
    if exposed_documents:
        dorking_section = (
            "\n\nDocumenti e file sensibili indicizzati pubblicamente (Google Dorking):\n"
            f"```json\n{json.dumps(exposed_documents, indent=2, ensure_ascii=False)}\n```\n"
        )

    user_prompt = (
        "Di seguito i dati OSINT sui breach email del dominio target:\n\n"
        f"```json\n{json.dumps(data_json, indent=2, ensure_ascii=False)}\n```\n"
        f"{subdomain_section}"
        f"{dorking_section}\n"
        "Scrivi un report esecutivo di Threat Intelligence strutturato con:\n"
        "1. Sommario del rischio\n"
        "2. Email più a rischio e relative esposizioni\n"
        "3. Vettori di attacco probabili (credential stuffing, phishing)\n"
        "4. Analisi dei sottodomini a rischio (se presenti)\n"
        "5. Analisi dei documenti esposti e rischio Data Leakage / IDOR (se presenti)\n"
        "6. Raccomandazioni immediate\n"
    )

    if provider == "gemini":
        return _call_gemini(api_key, model_name, user_prompt)
    if provider == "openai":
        return _call_openai(api_key, model_name, user_prompt)

    raise ValueError(f"Provider non supportato: '{provider}'. Usare 'gemini' o 'openai'.")


def _call_gemini(api_key: str, model_name: str, user_prompt: str) -> str:
    """Call a Gemini model using the google-genai SDK."""
    try:
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model=model_name,
            contents=user_prompt,
            config=genai_types.GenerateContentConfig(
                system_instruction=_SYSTEM_PROMPT,
                temperature=0.3,
            ),
        )
        return response.text or ""
    except Exception as exc:
        raise RuntimeError(f"Gemini API error: {exc}") from exc


def _call_openai(api_key: str, model_name: str, user_prompt: str) -> str:
    """Call an OpenAI model."""
    try:
        client = OpenAI(api_key=api_key)
        completion = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.3,
        )
        return completion.choices[0].message.content or ""
    except Exception as exc:
        raise RuntimeError(f"OpenAI API error: {exc}") from exc
