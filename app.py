"""OSINT Risk Mapper — entry point.

Passive Threat Intelligence tool for corporate domains. Two analysis pipelines:
  1. Email Breach (Hunter.io → Leak-Lookup → AI report on credential exposure)
  2. Network Intel (DNS → ZoomEye + Censys + LeakIX → merged host table + AI report)

No active scanning — all data comes from pre-indexed public sources.

Usage:
    streamlit run app.py
"""

import pandas as pd
import streamlit as st

from modules.ai_analyzer import generate_risk_report
from modules.llm_client import analyze_with_gemini, analyze_with_openai_compat
from modules.merger import merge_sources, to_dataframe
from modules.osint_dorking import search_exposed_documents
from modules.osint_hunter import fetch_emails_for_domain
from modules.osint_leaklookup import check_emails_for_breaches
from modules.osint_subdomains import get_subdomains
from modules.resolver import resolve_target
from modules.censys_client import fetch_censys
from modules.leakix_client import fetch_leakix
from modules.zoomeye_client import fetch_zoomeye
from modules.ui import render_host_metrics, render_consolidated_table
from utils.config import get_api_keys

_GEMINI_MODELS: dict[str, str] = {
    "Gemini 2.5 Flash": "gemini-2.5-flash",
    "Gemini 2.5 Flash-Lite": "gemini-2.5-flash-lite-preview-06-17",
}


# ── Sidebar ────────────────────────────────────────────────────────────────────

def _key_field(
    label: str,
    env_value: str,
    session_key: str,
    help_text: str = "",
) -> str:
    """Render a key input: green badge if loaded from .env, password field otherwise."""
    if env_value:
        st.success(f"{label} caricata da .env ✓")
        return env_value
    return st.text_input(label, type="password", key=session_key, help=help_text)


def _render_sidebar(env: dict[str, str]) -> dict:
    """Build the unified sidebar and return the active configuration."""
    with st.sidebar:
        st.header("⚙️ Configurazione")
        st.markdown("---")

        # ── AI provider ───────────────────────────────────────────────────────
        st.subheader("🤖 Modello AI")
        ai_choice = st.selectbox(
            "Provider",
            options=["Gemini 2.5 Flash", "Gemini 2.5 Flash-Lite", "OpenAI-Compatible"],
        )

        if ai_choice in _GEMINI_MODELS:
            provider = "gemini"
            model_name = _GEMINI_MODELS[ai_choice]
            openai_base_url = "https://api.openai.com/v1"
            openai_model = "gpt-4o-mini"
            ai_key = _key_field(
                "Gemini API Key", env["GEMINI_API_KEY"], "gemini_key",
                "Google AI Studio — aistudio.google.com",
            )
        else:
            provider = "openai_compat"
            model_name = ""
            ai_key = _key_field(
                "OpenAI API Key", env["OPENAI_API_KEY"], "openai_key",
            )
            openai_base_url = st.text_input(
                "Base URL", value="https://api.openai.com/v1",
                help="Per Ollama locale: http://localhost:11434/v1",
            )
            openai_model = st.text_input(
                "Modello", value="gpt-4o-mini",
                help="Es: gpt-4o · llama3.2",
            )
            model_name = openai_model

        st.markdown("---")

        # ── Email Breach sources ──────────────────────────────────────────────
        st.subheader("📧 Email Breach")
        hunter_key = _key_field(
            "Hunter.io API Key", env["HUNTER_API_KEY"], "hunter_key",
            "hunter.io — email discovery per dominio",
        )
        leaklookup_key = _key_field(
            "Leak-Lookup API Key", env["LEAKLOOKUP_API_KEY"], "leaklookup_key",
            "leak-lookup.com — breach database",
        )

        st.markdown("---")

        # ── Network Intel sources ─────────────────────────────────────────────
        st.subheader("🌐 Network Intel")
        zoomeye_key = _key_field(
            "ZoomEye API Key", env["ZOOMEYE_API_KEY"], "zoomeye_key",
            "zoomeye.org — host search",
        )
        st.markdown("**Censys**")
        censys_id = _key_field(
            "Censys API ID", env["CENSYS_API_ID"], "censys_id",
            "search.censys.io/account/api",
        )
        censys_secret = _key_field(
            "Censys API Secret", env["CENSYS_API_SECRET"], "censys_secret",
        )
        leakix_key = _key_field(
            "LeakIX API Key", env["LEAKIX_API_KEY"], "leakix_key",
            "leakix.net — leak & service events",
        )

        st.markdown("---")

        # ── Google Dorking ────────────────────────────────────────────────────
        st.subheader("🔎 Google Dorking")
        google_search_key = _key_field(
            "Google Search API Key", env["GOOGLE_SEARCH_API_KEY"], "google_search_key",
            "console.cloud.google.com — Custom Search JSON API",
        )
        google_cx_id = _key_field(
            "Google CX ID", env["GOOGLE_CX_ID"], "google_cx_id",
            "programmablesearchengine.google.com — Search Engine ID",
        )

        st.markdown("---")
        st.caption(
            "Crea un file `.env` dal template `.env.example` per evitare "
            "di inserire le chiavi ad ogni sessione."
        )

    return {
        "provider": provider,
        "model_name": model_name,
        "ai_key": ai_key,
        "openai_base_url": openai_base_url,
        "openai_model": openai_model,
        "hunter_key": hunter_key,
        "leaklookup_key": leaklookup_key,
        "zoomeye_key": zoomeye_key,
        "censys_id": censys_id,
        "censys_secret": censys_secret,
        "leakix_key": leakix_key,
        "google_search_key": google_search_key,
        "google_cx_id": google_cx_id,
    }


# ── Email Breach helpers ───────────────────────────────────────────────────────

def _build_breach_dataframe(breach_data: dict[str, list[str]]) -> pd.DataFrame:
    rows = []
    for email, sources in breach_data.items():
        compromised = bool(sources)
        rows.append({
            "Indirizzo Email": email,
            "Stato": "🔴 Compromessa" if compromised else "🟢 Non rilevata",
            "Fonti del Leak": ", ".join(sources) if sources else "—",
            "_compromised": compromised,
        })
    return pd.DataFrame(rows)


def _render_breach_table(df: pd.DataFrame) -> None:
    display = df.drop(columns=["_compromised"])

    def colour_row(row: pd.Series) -> list[str]:
        bg = (
            "background-color: #ffd6d6"
            if df.loc[row.name, "_compromised"]
            else "background-color: #d6f5d6"
        )
        return [bg] * len(row)

    st.dataframe(
        display.style.apply(colour_row, axis=1).hide(axis="index"),
        use_container_width=True,
    )


def _run_subdomain_pipeline(
    domain: str, tab: "st.delta_generator.DeltaGenerator"
) -> list[str]:
    """Fetch subdomains via crt.sh CT logs and render results inside `tab`.

    Returns the list of subdomains found (empty list on failure).
    """
    with tab:
        with st.spinner(f"🔗 Enumerazione sottodomini via Certificate Transparency per **{domain}**…"):
            try:
                subdomains = get_subdomains(domain)
            except RuntimeError as exc:
                st.error(f"❌ {exc}")
                return []

        if not subdomains:
            st.warning(f"⚠️ Nessun sottodominio trovato per **{domain}** su crt.sh.")
            return []

        st.success(f"✅ **{len(subdomains)} sottodomini unici** rilevati via Certificate Transparency.")

        df = pd.DataFrame({"Sottodomini Rilevati": subdomains})
        st.dataframe(df.style.hide(axis="index"), use_container_width=True)

        with st.expander("📦 Dati grezzi (debug)"):
            st.json(subdomains)

    return subdomains


def _run_email_breach_pipeline(
    domain: str,
    config: dict,
    tab: "st.delta_generator.DeltaGenerator",
    subdomains: list[str] | None = None,
    exposed_documents: list[dict[str, str]] | None = None,
) -> None:
    """Execute Hunter.io → Leak-Lookup → AI report and render inside `tab`."""
    with tab:
        if not config["hunter_key"]:
            st.warning("⚠️ Hunter.io API Key non configurata — pipeline email disabilitata.")
            return
        if not config["leaklookup_key"]:
            st.warning("⚠️ Leak-Lookup API Key non configurata — pipeline email disabilitata.")
            return

        with st.spinner(f"📧 Ricerca email su Hunter.io per **{domain}**…"):
            try:
                emails = fetch_emails_for_domain(domain, config["hunter_key"])
            except ValueError as exc:
                st.error(f"❌ {exc}")
                return
            except RuntimeError as exc:
                st.error(f"❌ {exc}")
                return

        if not emails:
            st.warning(
                f"⚠️ Hunter.io non ha trovato email per **{domain}**. "
                "Il dominio potrebbe non essere indicizzato."
            )
            return

        st.info(f"📧 Trovate **{len(emails)} email** associate a `{domain}`.")

        with st.spinner(f"🔎 Breach check su Leak-Lookup per {len(emails)} email…"):
            try:
                breach_data = check_emails_for_breaches(emails, config["leaklookup_key"])
            except ValueError as exc:
                st.error(f"❌ {exc}")
                return

        compromised = sum(1 for v in breach_data.values() if v)
        st.success(f"✅ {compromised}/{len(breach_data)} email con breach rilevati.")

        if config["ai_key"]:
            with st.spinner("🤖 Generazione report AI (email breach)…"):
                try:
                    report = generate_risk_report(
                        data_json=breach_data,
                        provider="gemini" if config["provider"] == "gemini" else "openai",
                        model_name=config["model_name"],
                        api_key=config["ai_key"],
                        subdomains=subdomains or [],
                        exposed_documents=exposed_documents or [],
                    )
                    st.subheader("🤖 Report AI — Credential Exposure")
                    st.markdown(report)
                    st.markdown("---")
                except RuntimeError as exc:
                    st.warning(f"⚠️ Report AI non disponibile: {exc}")
        else:
            st.info("ℹ️ AI API Key non configurata — report AI saltato.")

        st.subheader("📊 Dettaglio Email e Breach")
        df = _build_breach_dataframe(breach_data)
        _render_breach_table(df)

        with st.expander("📦 Dati grezzi (debug)"):
            st.json(breach_data)


# ── Google Dorking helpers ─────────────────────────────────────────────────────

def _run_dorking_pipeline(
    domain: str,
    config: dict,
    tab: "st.delta_generator.DeltaGenerator",
) -> list[dict[str, str]]:
    """Run Google Dorking via Custom Search API and render results inside `tab`.

    Returns list of exposed document dicts (empty on skip or no results).
    """
    with tab:
        if not config["google_search_key"] or not config["google_cx_id"]:
            st.warning(
                "⚠️ Google Search API Key o CX ID non configurati — "
                "modulo Dorking saltato. Configura `GOOGLE_SEARCH_API_KEY` e "
                "`GOOGLE_CX_ID` nella sidebar o nel file `.env`."
            )
            return []

        with st.spinner(f"🔎 Google Dorking su **{domain}** per file sensibili esposti…"):
            try:
                documents = search_exposed_documents(
                    domain=domain,
                    api_key=config["google_search_key"],
                    cx_id=config["google_cx_id"],
                )
            except RuntimeError as exc:
                st.error(f"❌ {exc}")
                return []

        if not documents:
            st.success("✅ Nessun documento sensibile indicizzato rilevato.")
            return []

        st.warning(
            f"⚠️ **{len(documents)} file sensibili** indicizzati pubblicamente rilevati."
        )

        with st.expander("📄 Documenti Sensibili Esposti (Google Dorking)", expanded=True):
            df = pd.DataFrame(documents).rename(
                columns={"title": "Nome File/Titolo", "url": "URL"}
            )
            st.dataframe(df.style.hide(axis="index"), use_container_width=True)

        with st.expander("📦 Dati grezzi (debug)"):
            st.json(documents)

    return documents


# ── Network Intel helpers ──────────────────────────────────────────────────────

def _run_network_intel_pipeline(
    domain: str, config: dict, tab: "st.delta_generator.DeltaGenerator"
) -> None:
    """Execute DNS → ZoomEye + Censys + LeakIX → merge → AI report inside `tab`."""
    with tab:
        has_source = (
            bool(config["zoomeye_key"])
            or (bool(config["censys_id"]) and bool(config["censys_secret"]))
            or bool(config["leakix_key"])
        )
        if not has_source:
            st.warning(
                "⚠️ Nessuna fonte Network Intel configurata "
                "(ZoomEye, Censys o LeakIX). Pipeline disabilitata."
            )
            return

        with st.spinner(f"🌐 Risoluzione DNS di **{domain}**…"):
            try:
                ip = resolve_target(domain)
            except ValueError as exc:
                st.error(f"❌ {exc}")
                return

        if ip != domain:
            st.info(f"🌐 `{domain}` risolto in `{ip}`")

        zoomeye_data: dict = {}
        censys_data: dict = {}
        leakix_data: dict = {}
        sources_queried: list[str] = []

        if config["zoomeye_key"]:
            sources_queried.append("ZoomEye")
            with st.spinner("🔍 Interrogazione ZoomEye…"):
                try:
                    zoomeye_data = fetch_zoomeye(config["zoomeye_key"], ip)
                    if not zoomeye_data:
                        st.info("ℹ️ ZoomEye: nessun dato per questo host.")
                except ValueError as exc:
                    st.error(f"❌ {exc}")
                except RuntimeError as exc:
                    st.warning(f"⚠️ {exc}")

        if config["censys_id"] and config["censys_secret"]:
            sources_queried.append("Censys")
            with st.spinner("🔍 Interrogazione Censys…"):
                try:
                    censys_data = fetch_censys(config["censys_id"], config["censys_secret"], ip)
                    if not censys_data:
                        st.info("ℹ️ Censys: nessun dato per questo host.")
                except ValueError as exc:
                    st.error(f"❌ {exc}")
                except RuntimeError as exc:
                    st.warning(f"⚠️ {exc}")

        if config["leakix_key"]:
            sources_queried.append("LeakIX")
            with st.spinner("🔍 Interrogazione LeakIX…"):
                try:
                    leakix_data = fetch_leakix(config["leakix_key"], ip)
                    if not leakix_data:
                        st.info("ℹ️ LeakIX: nessun evento per questo host.")
                except ValueError as exc:
                    st.error(f"❌ {exc}")
                except RuntimeError as exc:
                    st.warning(f"⚠️ {exc}")

        merged = merge_sources(
            zoomeye=zoomeye_data,
            censys=censys_data,
            leakix=leakix_data,
            target_ip=ip,
            sources_queried=sources_queried,
        )

        if not merged["sources_ok"]:
            st.error("❌ Nessuna fonte ha restituito dati per questo host.")
            return

        sources_label = ", ".join(merged["sources_ok"])
        st.success(
            f"✅ Dati raccolti da: **{sources_label}** · "
            f"IP: `{ip}` · Org: {merged.get('org') or 'N/D'}"
        )

        render_host_metrics(merged)
        st.markdown("---")

        if config["ai_key"]:
            with st.spinner("🤖 Generazione report AI (network intel)…"):
                try:
                    if config["provider"] == "gemini":
                        host_report = analyze_with_gemini(
                            api_key=config["ai_key"],
                            model_name=config["model_name"],
                            data=merged,
                        )
                    else:
                        host_report = analyze_with_openai_compat(
                            api_key=config["ai_key"],
                            base_url=config["openai_base_url"],
                            model=config["openai_model"],
                            data=merged,
                        )
                    st.subheader("🤖 Report AI — Network Risk")
                    st.markdown(host_report)
                    st.markdown("---")
                except RuntimeError as exc:
                    st.warning(f"⚠️ Report AI non disponibile: {exc}")
        else:
            st.info("ℹ️ AI API Key non configurata — report AI saltato.")

        st.subheader("🗂️ Porte, Servizi e Vulnerabilità")
        df = to_dataframe(merged)
        render_consolidated_table(df)

        with st.expander("📦 Dati aggregati grezzi (debug)"):
            debug = {
                k: (list(v.values()) if k == "ports" else v)
                for k, v in merged.items()
            }
            st.json(debug)


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    st.set_page_config(
        page_title="OSINT Risk Mapper",
        page_icon="🔍",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    env = get_api_keys()
    config = _render_sidebar(env)

    st.title("🔍 OSINT Risk Mapper")
    st.caption(
        "Threat Intelligence passiva · Email Breach + Network Intel per domini aziendali"
    )
    st.markdown("---")

    st.info(
        "⚠️ **Strumento OSINT passivo** — interroga esclusivamente database pubblici e "
        "API di terze parti. Nessuna connessione diretta al target. "
        "Utilizzare solo su domini per cui si dispone di autorizzazione esplicita."
    )
    st.markdown("---")

    col_input, col_btn = st.columns([4, 1])
    with col_input:
        domain: str = st.text_input(
            "Dominio target",
            placeholder="es: azienda.it",
            help="Nome a dominio da analizzare (senza http://)",
            label_visibility="collapsed",
        )
    with col_btn:
        analyze_btn = st.button("🔍 Analizza", use_container_width=True, type="primary")

    if not analyze_btn:
        st.markdown(
            """
            #### Come usare OSINT Risk Mapper
            1. Configura le **chiavi API** nella sidebar (o crea `.env` da `.env.example`).
            2. Seleziona il **modello AI** per i report.
            3. Inserisci un **dominio aziendale** (es. `azienda.it`).
            4. Clicca **Analizza** — verranno eseguite tutte le pipeline:

            | Tab | Pipeline | Fonti |
            |-----|----------|-------|
            | 📧 Email Breach | Discovery email → Breach check → AI report | Hunter.io + Leak-Lookup |
            | 🌐 Network Intel | DNS resolve → Host scan passivo → AI report | ZoomEye + Censys + LeakIX |
            | 🔗 Subdomain Enumeration | CT log query → dedup → tabella sottodomini | crt.sh (gratuito, no API key) |
            | 📄 Google Dorking | Dork query → file sensibili esposti | Google Custom Search JSON API |
            """
        )
        return

    domain = (
        domain.strip().lower()
        .removeprefix("https://")
        .removeprefix("http://")
        .rstrip("/")
    )

    if not domain:
        st.error("❌ Inserisci un nome a dominio prima di procedere.")
        return

    if not config["ai_key"]:
        st.warning(
            "⚠️ AI API Key non configurata — i report testuali AI non verranno generati. "
            "I dati OSINT grezzi saranno comunque mostrati."
        )

    tab_email, tab_network, tab_subdomains, tab_dorking = st.tabs([
        "📧 Email Breach", "🌐 Network Intel", "🔗 Subdomain Enumeration",
        "📄 Google Dorking",
    ])

    subdomains = _run_subdomain_pipeline(domain, tab_subdomains)
    exposed_documents = _run_dorking_pipeline(domain, config, tab_dorking)
    _run_email_breach_pipeline(
        domain, config, tab_email,
        subdomains=subdomains,
        exposed_documents=exposed_documents,
    )
    _run_network_intel_pipeline(domain, config, tab_network)


if __name__ == "__main__":
    main()
