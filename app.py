"""OSINT Risk Mapper — entry point.

Passive Threat Intelligence tool for corporate domains. Two analysis pipelines:
  1. Email Breach (Hunter.io → Leak-Lookup → AI report on credential exposure)
  2. Network Intel (DNS → ZoomEye + Censys + LeakIX → merged host table + AI report)

No active scanning — all data comes from pre-indexed public sources.

Usage:
    streamlit run app.py
"""

from __future__ import annotations

import pandas as pd
import streamlit as st

from modules.ai_analyzer import generate_risk_report
from modules.llm_client import analyze_with_gemini
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
from modules.dashboard_map import render_heatmap, generate_mock_province_data
from utils.config import get_api_keys

_GEMINI_MODEL = "gemini-2.5-flash"
_MAX_SCANS_PER_SESSION = 5


# ── Sidebar ────────────────────────────────────────────────────────────────────

def _status(label: str, ok: bool) -> None:
    icon = "✅" if ok else "❌"
    st.markdown(f"{icon} {label}")


def _render_sidebar(env: dict[str, str]) -> dict:
    """Build sidebar with mode selector and feature status indicators."""
    with st.sidebar:
        st.header("🗺️ Modalità")
        mode = st.radio(
            "Seleziona modalità",
            ["Analisi Target", "Heatmap Territoriale"],
            label_visibility="collapsed",
        )
        st.markdown("---")

        st.header("⚙️ Stato Servizi")
        _status("Email Breach (Hunter.io)", bool(env["HUNTER_API_KEY"]))
        _status("Breach DB (Leak-Lookup)", bool(env["LEAKLOOKUP_API_KEY"]))
        _status("Network Intel (ZoomEye)", bool(env["ZOOMEYE_API_KEY"]))
        _status(
            "Network Intel (Censys)",
            bool(env["CENSYS_API_ID"]) and bool(env["CENSYS_API_SECRET"]),
        )
        _status("Network Intel (LeakIX)", bool(env["LEAKIX_API_KEY"]))
        _status("Google Dorking", bool(env["GOOGLE_SEARCH_API_KEY"]) and bool(env["GOOGLE_CX_ID"]))
        _status("AI Reports (Gemini)", bool(env["GEMINI_API_KEY"]))
        st.markdown("---")
        st.caption("Subdomain Enumeration (crt.sh) sempre attivo — nessuna key richiesta.")

    return {
        "mode": mode,
        "provider": "gemini",
        "model_name": _GEMINI_MODEL,
        "ai_key": env["GEMINI_API_KEY"],
        "hunter_key": env["HUNTER_API_KEY"],
        "leaklookup_key": env["LEAKLOOKUP_API_KEY"],
        "zoomeye_key": env["ZOOMEYE_API_KEY"],
        "censys_id": env["CENSYS_API_ID"],
        "censys_secret": env["CENSYS_API_SECRET"],
        "leakix_key": env["LEAKIX_API_KEY"],
        "google_search_key": env["GOOGLE_SEARCH_API_KEY"],
        "google_cx_id": env["GOOGLE_CX_ID"],
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
        width="stretch",
    )


def _run_subdomain_pipeline(
    domain: str, tab: "st.delta_generator.DeltaGenerator"
) -> list[str]:
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
        st.dataframe(df.style.hide(axis="index"), width="stretch")

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
            except (ValueError, RuntimeError) as exc:
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
                        provider="gemini",
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
            st.info("ℹ️ Gemini API Key non configurata — report AI saltato.")

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
    with tab:
        if not config["google_search_key"] or not config["google_cx_id"]:
            st.warning(
                "⚠️ Google Search API Key o CX ID non configurati — modulo Dorking saltato."
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
            st.dataframe(df.style.hide(axis="index"), width="stretch")

        with st.expander("📦 Dati grezzi (debug)"):
            st.json(documents)

    return documents


# ── Network Intel helpers ──────────────────────────────────────────────────────

def _run_network_intel_pipeline(
    domain: str, config: dict, tab: "st.delta_generator.DeltaGenerator"
) -> None:
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
                    host_report = analyze_with_gemini(
                        api_key=config["ai_key"],
                        model_name=config["model_name"],
                        data=merged,
                    )
                    st.subheader("🤖 Report AI — Network Risk")
                    st.markdown(host_report)
                    st.markdown("---")
                except RuntimeError as exc:
                    st.warning(f"⚠️ Report AI non disponibile: {exc}")
        else:
            st.info("ℹ️ Gemini API Key non configurata — report AI saltato.")

        st.subheader("🗂️ Porte, Servizi e Vulnerabilità")
        df = to_dataframe(merged)
        render_consolidated_table(df)

        with st.expander("📦 Dati aggregati grezzi (debug)"):
            debug = {
                k: (list(v.values()) if k == "ports" else v)
                for k, v in merged.items()
            }
            st.json(debug)


# ── Heatmap page ───────────────────────────────────────────────────────────────

_CYBER_CSS = """
<style>
.stApp { background-color: #050d1a !important; }
.cyber-title {
    font-family: monospace; color: #00d4ff;
    text-shadow: 0 0 12px rgba(0,212,255,0.4);
    font-size: 1.6rem; font-weight: bold;
    border-bottom: 1px solid rgba(0,212,255,0.25);
    padding-bottom: 8px; margin-bottom: 16px;
}
.cyber-banner {
    font-family: monospace; color: #00d4ff;
    background: #0a1628;
    border: 1px solid rgba(0,212,255,0.25);
    border-left: 3px solid #00d4ff;
    padding: 10px 16px; font-size: 0.82rem;
    margin-bottom: 20px; line-height: 1.6;
}
.kpi-card {
    background: #0a1628;
    border: 1px solid rgba(0,212,255,0.2);
    border-top: 2px solid #00d4ff;
    padding: 18px 12px; text-align: center;
    font-family: monospace;
}
.kpi-value {
    color: #00d4ff; font-size: 2rem; font-weight: bold;
    text-shadow: 0 0 10px rgba(0,212,255,0.5);
    line-height: 1.1;
}
.kpi-label {
    color: rgba(0,212,255,0.55); font-size: 0.65rem;
    letter-spacing: 2px; margin-top: 6px;
}
.cyber-section {
    font-family: monospace; color: #00d4ff;
    font-size: 0.9rem; letter-spacing: 1px;
    border-bottom: 1px solid rgba(0,212,255,0.15);
    padding-bottom: 4px; margin: 20px 0 10px;
}
[data-testid="stDataFrame"] {
    border: 1px solid rgba(0,212,255,0.2) !important;
}
</style>
"""


def _kpi_card(value: str, label: str) -> str:
    return (
        f'<div class="kpi-card">'
        f'<div class="kpi-value">{value}</div>'
        f'<div class="kpi-label">{label}</div>'
        f'</div>'
    )


def _render_heatmap_page() -> None:
    st.markdown(_CYBER_CSS, unsafe_allow_html=True)

    st.markdown(
        '<div class="cyber-title">&gt; RISK_MAP :: PROVINCIA DI FOGGIA</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        '<div class="cyber-banner">'
        "// GDPR COMPLIANCE — i dati sono aggregati a livello comunale.<br>"
        "// Nessuna informazione identificativa delle singole aziende è esposta.<br>"
        "// Fonte: dati simulati a scopo dimostrativo."
        "</div>",
        unsafe_allow_html=True,
    )

    df = generate_mock_province_data()
    tot_pmi = int(df["PMI_Analizzate"].sum())
    tot_vuln = int(df["Vulnerabilita_Critiche"].sum())
    top_comune = df.loc[df["Rischio_Medio"].idxmax(), "Comune"].upper()
    avg_risk = round(float(df["Rischio_Medio"].mean()), 1)

    k1, k2, k3, k4 = st.columns(4)
    k1.markdown(_kpi_card(str(tot_pmi), "PMI ANALIZZATE"), unsafe_allow_html=True)
    k2.markdown(_kpi_card(str(tot_vuln), "VULN CRITICHE"), unsafe_allow_html=True)
    k3.markdown(_kpi_card(top_comune, "TOP RISK"), unsafe_allow_html=True)
    k4.markdown(_kpi_card(str(avg_risk), "RISCHIO MEDIO"), unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    with st.spinner("// loading geo-data..."):
        fig = render_heatmap()

    if fig is None:
        st.error(
            "❌ Impossibile caricare il GeoJSON remoto. "
            "Verifica la connessione internet e riprova."
        )
    else:
        st.plotly_chart(fig, use_container_width=True)

    st.markdown(
        '<div class="cyber-section">&gt; DATA_TABLE :: COMUNI</div>',
        unsafe_allow_html=True,
    )
    st.dataframe(df, width="stretch", hide_index=True)


# ── Analysis page ───────────────────────────────────────────────────────────────

def _render_analysis_page(config: dict) -> None:
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

    if "scan_count" not in st.session_state:
        st.session_state.scan_count = 0

    col_input, col_btn = st.columns([4, 1])
    with col_input:
        domain: str = st.text_input(
            "Dominio target",
            placeholder="es: azienda.it",
            help="Nome a dominio da analizzare (senza http://)",
            label_visibility="collapsed",
        )
    with col_btn:
        analyze_btn = st.button("🔍 Analizza", width="stretch", type="primary")

    remaining = _MAX_SCANS_PER_SESSION - st.session_state.scan_count
    if remaining < _MAX_SCANS_PER_SESSION:
        st.caption(f"Analisi questa sessione: {st.session_state.scan_count}/{_MAX_SCANS_PER_SESSION}")

    if not analyze_btn:
        st.markdown(
            """
            #### Come usare OSINT Risk Mapper
            1. Inserisci un **dominio aziendale** nel campo sopra (es. `azienda.it`)
            2. Clicca **Analizza** — le pipeline vengono eseguite automaticamente

            | Tab | Pipeline | Fonti |
            |-----|----------|-------|
            | 📧 Email Breach | Discovery email → Breach check → AI report | Hunter.io + Leak-Lookup |
            | 🌐 Network Intel | DNS resolve → Host scan passivo → AI report | ZoomEye + Censys + LeakIX |
            | 🔗 Subdomain Enumeration | CT log query → dedup → tabella sottodomini | crt.sh (gratuito) |
            | 📄 Google Dorking | Dork query → file sensibili esposti | Google Custom Search |
            """
        )
        return

    if st.session_state.scan_count >= _MAX_SCANS_PER_SESSION:
        st.warning(
            f"⚠️ Limite di {_MAX_SCANS_PER_SESSION} analisi per sessione raggiunto. "
            "Ricarica la pagina per continuare."
        )
        st.stop()

    domain = (
        domain.strip().lower()
        .removeprefix("https://")
        .removeprefix("http://")
        .rstrip("/")
    )

    if not domain:
        st.error("❌ Inserisci un nome a dominio prima di procedere.")
        return

    st.session_state.scan_count += 1

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

    if config["mode"] == "Heatmap Territoriale":
        _render_heatmap_page()
    else:
        _render_analysis_page(config)


if __name__ == "__main__":
    main()
