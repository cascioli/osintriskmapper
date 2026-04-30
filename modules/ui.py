"""
Streamlit UI components for OSINT Risk Mapper.
All user-facing text is in Italian; code comments are in English.
"""

from typing import Any

import pandas as pd
import streamlit as st


def render_ethical_banner() -> None:
    """Display a prominent ethical-use warning at the top of the page."""
    st.warning(
        "⚠️ **OSINT Risk Mapper** — Tool per esclusiva analisi passiva e ricerca "
        "autorizzata. Non eseguire analisi su sistemi senza il consenso esplicito "
        "del proprietario. Uso improprio può costituire reato."
    )


def render_sidebar() -> dict[str, Any]:
    """
    Render the configuration sidebar and return a dict of user settings.

    Returns:
        {
            zoomeye_key: str,
            censys_id: str,
            censys_secret: str,
            leakix_key: str,
            llm_provider: str,       # "gemini" | "openai_compat"
            llm_key: str,
            gemini_model: str,
            openai_base_url: str,
            openai_model: str,
        }
    """
    st.sidebar.title("⚙️ Configurazione")
    st.sidebar.markdown("---")

    # ── OSINT Sources ─────────────────────────────────────────────────────────
    st.sidebar.subheader("🔍 Sorgenti OSINT")
    st.sidebar.caption("Configura almeno una fonte per avviare l'analisi.")

    zoomeye_key: str = st.sidebar.text_input(
        "ZoomEye API Key",
        type="password",
        help="Ottieni la chiave su zoomeye.org › Account",
        placeholder="ZoomEye key…",
    )

    st.sidebar.markdown("**Censys**")
    censys_id: str = st.sidebar.text_input(
        "Censys API ID",
        type="password",
        help="Disponibile su search.censys.io/account/api",
        placeholder="API ID…",
    )
    censys_secret: str = st.sidebar.text_input(
        "Censys API Secret",
        type="password",
        help="Usa API ID + Secret per autenticare le richieste Censys",
        placeholder="API Secret…",
    )

    leakix_key: str = st.sidebar.text_input(
        "LeakIX API Key",
        type="password",
        help="Registrati su leakix.net per ottenere la chiave gratuita",
        placeholder="LeakIX key…",
    )

    st.sidebar.markdown("---")

    # ── LLM provider ─────────────────────────────────────────────────────────
    st.sidebar.subheader("🤖 Analisi AI")
    provider_label: str = st.sidebar.selectbox(
        "Provider LLM",
        options=["Gemini (Google)", "OpenAI-Compatible"],
        help="Scegli il backend per la generazione del report",
    )

    llm_provider = "gemini" if provider_label == "Gemini (Google)" else "openai_compat"
    llm_key = ""
    gemini_model = "gemini-2.5-flash"
    openai_base_url = "https://api.openai.com/v1"
    openai_model = "gpt-4o-mini"

    if llm_provider == "gemini":
        llm_key = st.sidebar.text_input(
            "Gemini API Key",
            type="password",
            help="Chiave API Google AI Studio — aistudio.google.com",
            placeholder="AIza…",
        )
        gemini_model = st.sidebar.selectbox(
            "Modello Gemini",
            options=["gemini-2.5-flash", "gemini-2.5-flash-lite"],
            help="gemini-2.5-flash: più capace · gemini-2.5-flash-lite: più veloce",
        )
    else:
        llm_key = st.sidebar.text_input(
            "API Key",
            type="password",
            help="Chiave del provider scelto (OpenAI, Anthropic proxy, ecc.)",
        )
        openai_base_url = st.sidebar.text_input(
            "Base URL",
            value="https://api.openai.com/v1",
            help="Per Ollama locale: http://localhost:11434/v1",
        )
        openai_model = st.sidebar.text_input(
            "Nome Modello",
            value="gpt-4o-mini",
            help="Es: gpt-4o · claude-3-5-haiku-20241022 · llama3.2",
        )

    st.sidebar.markdown("---")
    st.sidebar.caption(
        "🔒 Le chiavi API non vengono mai salvate su disco né trasmesse "
        "a server terzi — usate solo per le chiamate API dirette."
    )

    return {
        "zoomeye_key": zoomeye_key,
        "censys_id": censys_id,
        "censys_secret": censys_secret,
        "leakix_key": leakix_key,
        "llm_provider": llm_provider,
        "llm_key": llm_key,
        "gemini_model": gemini_model,
        "openai_base_url": openai_base_url,
        "openai_model": openai_model,
    }


def render_host_metrics(merged: dict[str, Any]) -> None:
    """Display key host attributes as a row of metric cards."""
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("🌐 IP", merged.get("ip", "—"))
    c2.metric("🏳️ Paese", merged.get("country", "—") or "—")
    c3.metric("🏢 Organizzazione", merged.get("org", "—") or "—")
    c4.metric("🔌 Porte Rilevate", len(merged.get("ports", {})))
    sources_ok: list[str] = merged.get("sources_ok", [])
    c5.metric("📡 Fonti con Dati", f"{len(sources_ok)}/3")


def render_ai_report(report: str) -> None:
    """Display the AI-generated risk analysis in a highlighted info box."""
    st.subheader("📋 Report AI — Analisi del Rischio")
    st.info(report)


def render_consolidated_table(df: pd.DataFrame) -> None:
    """
    Render the unified consolidated table of ports, services, and findings.

    Columns: Porta | Servizio | Dettagli/Banner | Vulnerabilità (CVE/Leak) | Fonti

    Args:
        df: DataFrame from merger.to_dataframe.
    """
    if df.empty:
        st.info("ℹ️ Nessun servizio rilevato dalle fonti OSINT per questo host.")
        return

    st.dataframe(
        df,
        width="stretch",
        hide_index=True,
        column_config={
            "Porta": st.column_config.TextColumn("Porta", width="small"),
            "Servizio": st.column_config.TextColumn("Servizio", width="medium"),
            "Dettagli/Banner": st.column_config.TextColumn("Dettagli/Banner", width="large"),
            "Vulnerabilità (CVE/Leak)": st.column_config.TextColumn(
                "Vulnerabilità (CVE/Leak)", width="large"
            ),
            "Fonti": st.column_config.TextColumn("Fonti", width="small"),
        },
    )
