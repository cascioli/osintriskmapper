"""OSINT Risk Mapper — entry point.

Passive Threat Intelligence tool for corporate domains. Two analysis pipelines:
  1. Email Breach (Hunter.io → Leak-Lookup → AI report on credential exposure)
  2. Network Intel (DNS → ZoomEye + Censys + LeakIX → merged host table + AI report)

Synergistic mode adds three additional rounds:
  Round 2 — subdomain→network, network→targeted dorking, email-IP correlation
  Round 3 — LLM entity extraction + follow-up scans
  Final   — unified cross-correlated report + connection graph

No active scanning — all data comes from pre-indexed public sources.

Usage:
    streamlit run app.py
"""

from __future__ import annotations

import io
import zipfile
from datetime import datetime

import pandas as pd
import streamlit as st

from modules.merger import to_dataframe
from modules.ui import render_host_metrics, render_consolidated_table
from modules.dashboard_map import render_heatmap, generate_mock_province_data
from modules.scan_context import ScanContext
from modules.orchestrator import run_round1, run_round2, run_round3, run_final
from modules.graph_builder import render_connection_graph
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
        _status("Google Dorking (Serper.dev)", bool(env["SERPER_API_KEY"]) or bool(env["SERPAPI_KEY"]))
        _status("AI Reports (Gemini)", bool(env["GEMINI_API_KEY"]))
        st.markdown("---")

        st.header("⚙️ Impostazioni Analisi")
        max_subs = st.slider(
            "Max sottodomini da scansionare (Round 2)",
            min_value=5, max_value=50, value=20, step=5,
            key="max_subdomain_scans",
            help="Più sottodomini = più chiamate API ma analisi più completa.",
        )
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
        "serper_key": env["SERPER_API_KEY"],
        "serpapi_key": env["SERPAPI_KEY"],
        "max_subdomain_scans": max_subs,
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


def _render_idle_welcome() -> None:
    st.markdown("""
    #### Come usare OSINT Risk Mapper
    1. Inserisci un **dominio aziendale** nel campo sopra (es. `azienda.it`)
    2. Clicca **Analizza** — tutti i moduli vengono eseguiti automaticamente
    3. Monitora il progresso in tempo reale tramite la barra e il log terminale
    4. Al termine, esplora i risultati per sezione e scarica i report

    | Modulo | Fonte | Round |
    |--------|-------|-------|
    | Subdomain Enum | crt.sh | 1 |
    | Email Discovery + Breach | Hunter.io + Leak-Lookup | 1 |
    | Network Intel primario | ZoomEye + Censys + LeakIX | 1 |
    | Subdomain Network Scan | ZoomEye + Censys + LeakIX | 2 |
    | Targeted Dorking | Google Custom Search | 2 |
    | Email-IP Correlation | LeakIX | 2 |
    | LLM Entity Extraction | Gemini | 3 |
    | Unified Report + Graph | Gemini | Final |
    """)


def _render_running_phase(config: dict, domain: str) -> None:
    ctx = ScanContext(domain=domain, config=config)
    st.session_state.scan_log = []
    LOG_MAX = 40

    progress_bar = st.progress(0.0, text="Avvio analisi...")
    log_placeholder = st.empty()

    def log_fn(msg: str) -> None:
        st.session_state.scan_log.append(msg)
        lines = "\n".join(st.session_state.scan_log[-LOG_MAX:])
        log_placeholder.markdown(f"```\n{lines}\n```")

    def progress_fn(val: float) -> None:
        progress_bar.progress(val, text=f"Analisi in corso... {int(val * 100)}%")

    max_subs = config.get("max_subdomain_scans", 20)
    ctx = run_round1(ctx, log_fn=log_fn, progress_fn=progress_fn)
    ctx = run_round2(ctx, max_subs=max_subs, log_fn=log_fn, progress_fn=progress_fn)
    ctx = run_round3(ctx, log_fn=log_fn, progress_fn=progress_fn)
    ctx = run_final(ctx, log_fn=log_fn, progress_fn=progress_fn)

    st.session_state.scan_ctx = ctx
    st.session_state.scan_phase = "final"
    st.rerun()


def _build_csv_zip(ctx: ScanContext) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        if ctx.emails:
            zf.writestr("emails.csv", pd.DataFrame({"email": ctx.emails}).to_csv(index=False))
        if ctx.subdomains:
            zf.writestr("subdomains.csv", pd.DataFrame({"subdomain": ctx.subdomains}).to_csv(index=False))
        network_rows = []
        if ctx.primary_host:
            for p in ctx.primary_host.get("ports", {}).values():
                network_rows.append({
                    "ip": ctx.primary_ip, "subdomain": ctx.domain,
                    "port": p.get("port"), "service": p.get("service"), "product": p.get("product"),
                    "vulns": "; ".join(p.get("vulns", [])), "leaks": "; ".join(p.get("leaks", [])),
                })
        for r in ctx.subdomain_results:
            if r.merged_host:
                for p in r.merged_host.get("ports", {}).values():
                    network_rows.append({
                        "ip": r.ip, "subdomain": r.subdomain,
                        "port": p.get("port"), "service": p.get("service"), "product": p.get("product"),
                        "vulns": "; ".join(p.get("vulns", [])), "leaks": "; ".join(p.get("leaks", [])),
                    })
        if network_rows:
            zf.writestr("network.csv", pd.DataFrame(network_rows).to_csv(index=False))
        all_docs = ctx.exposed_documents + ctx.targeted_dork_results
        if all_docs:
            zf.writestr("documents.csv", pd.DataFrame(all_docs).to_csv(index=False))
        if ctx.email_ip_correlations:
            rows = [
                {"email": c.email, "breach_sources": "; ".join(c.breach_sources),
                 "correlated_ips": "; ".join(c.correlated_ips)}
                for c in ctx.email_ip_correlations
            ]
            zf.writestr("correlations.csv", pd.DataFrame(rows).to_csv(index=False))
        if ctx.exposed_services:
            rows = [
                {"ip": s.ip, "port": s.port, "service": s.service_name,
                 "product": s.product, "leak_labels": "; ".join(s.leak_labels)}
                for s in ctx.exposed_services
            ]
            zf.writestr("exposed_services.csv", pd.DataFrame(rows).to_csv(index=False))
    return buf.getvalue()


def _build_report_md(ctx: ScanContext) -> str:
    lines = [
        f"# OSINT Risk Mapper — {ctx.domain}",
        f"Generato: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## Riepilogo",
        f"- Sottodomini rilevati: {len(ctx.subdomains)}",
        f"- Email trovate: {len(ctx.emails)}",
        f"- Servizi esposti: {len(ctx.exposed_services)}",
        f"- Documenti esposti: {len(ctx.exposed_documents + ctx.targeted_dork_results)}",
        f"- Correlazioni email-IP: {sum(1 for c in ctx.email_ip_correlations if c.correlated_ips)}",
        f"- Entità Round 3: {len(ctx.follow_up_host_results)}",
        "",
    ]
    if ctx.unified_report:
        lines += ["---", "", ctx.unified_report]
    return "\n".join(lines)


def _render_final_phase(ctx: ScanContext) -> None:
    st.success(f"✅ Analisi completata per **{ctx.domain}**")

    n_correlated = sum(1 for c in ctx.email_ip_correlations if c.correlated_ips)
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Sottodomini", len(ctx.subdomains))
    c2.metric("Email", len(ctx.emails))
    c3.metric("Servizi esposti", len(ctx.exposed_services))
    c4.metric("Correlazioni email-IP", n_correlated)
    c5.metric("Entità Round 3", len(ctx.follow_up_host_results))

    date_str = datetime.now().strftime("%Y%m%d_%H%M")
    col_csv, col_pdf = st.columns(2)
    with col_csv:
        st.download_button(
            "⬇️ Scarica CSV (ZIP)", data=_build_csv_zip(ctx),
            file_name=f"osint_{ctx.domain}_{date_str}.zip",
            mime="application/zip", use_container_width=True,
        )
    with col_pdf:
        st.download_button(
            "⬇️ Scarica Report (Markdown)", data=_build_report_md(ctx),
            file_name=f"osint_report_{ctx.domain}_{date_str}.md",
            mime="text/markdown", use_container_width=True,
        )

    st.divider()

    with st.expander("📋 Report Unificato AI", expanded=True):
        if ctx.unified_report:
            st.markdown(ctx.unified_report)
        else:
            st.warning("Report non disponibile — Gemini API Key mancante.")

    with st.expander("🕸️ Grafo Connessioni", expanded=True):
        if ctx.graph_data:
            fig = render_connection_graph(ctx.graph_data)
            st.plotly_chart(fig, use_container_width=True)
            st.caption("🔵 Dominio · 🟣 IP · 🔷 Subdomain · 🟠 Email · 🔴 Breach · 🩷 Porta · 🟡 Documento")
        else:
            st.info("Grafo non disponibile.")

    with st.expander("⚠️ Servizi Sensibili", expanded=bool(ctx.exposed_services)):
        if ctx.exposed_services:
            svc_df = pd.DataFrame([
                {"IP": s.ip, "Porta": s.port, "Servizio": s.service_name, "Prodotto": s.product}
                for s in ctx.exposed_services
            ])
            st.dataframe(svc_df.style.hide(axis="index"), use_container_width=True)
        else:
            st.info("Nessun servizio sensibile rilevato.")

    with st.expander("📧 Email Breach", expanded=bool(ctx.breach_data)):
        if ctx.breach_data:
            df = _build_breach_dataframe(ctx.breach_data)
            _render_breach_table(df)
        else:
            st.info("Nessun dato email disponibile.")

    with st.expander("🔗 Correlazioni Email ↔ IP", expanded=n_correlated > 0):
        if n_correlated > 0:
            rows = [
                {"Email": c.email, "Breach Sources": ", ".join(c.breach_sources),
                 "IP Correlati": ", ".join(c.correlated_ips)}
                for c in ctx.email_ip_correlations if c.correlated_ips
            ]
            st.dataframe(pd.DataFrame(rows).style.hide(axis="index"), use_container_width=True)
        else:
            st.info("Nessuna correlazione email-IP rilevata.")

    with st.expander("🔗 Subdomain Enumeration", expanded=False):
        if ctx.subdomains:
            st.dataframe(
                pd.DataFrame({"Sottodominio": ctx.subdomains}).style.hide(axis="index"),
                use_container_width=True,
            )
        if ctx.primary_host and ctx.primary_host.get("sources_ok"):
            st.subheader("Network — IP Primario")
            render_host_metrics(ctx.primary_host)
            render_consolidated_table(to_dataframe(ctx.primary_host))

    all_docs = ctx.exposed_documents + ctx.targeted_dork_results
    with st.expander("📄 Documenti Esposti (Dorking)", expanded=bool(all_docs)):
        if all_docs:
            df = pd.DataFrame(all_docs).rename(columns={"title": "Titolo", "url": "URL"})
            st.dataframe(df.style.hide(axis="index"), use_container_width=True)
        else:
            st.info("Nessun documento esposto rilevato.")

    with st.expander("🤖 Entità Suggerite da Gemini (Round 3)",
                     expanded=bool(ctx.llm_suggested_ips or ctx.llm_suggested_domains)):
        col_ip, col_dom = st.columns(2)
        with col_ip:
            st.markdown("**IP suggeriti:**")
            for ip in ctx.llm_suggested_ips:
                st.code(ip)
        with col_dom:
            st.markdown("**Domini suggeriti:**")
            for dom in ctx.llm_suggested_domains:
                st.code(dom)

    with st.expander("📟 Log di Esecuzione", expanded=False):
        st.code("\n".join(st.session_state.get("scan_log", [])), language=None)


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
    st.caption("Threat Intelligence passiva · Email Breach + Network Intel per domini aziendali")
    st.markdown("---")
    st.info(
        "⚠️ **Strumento OSINT passivo** — interroga esclusivamente database pubblici e "
        "API di terze parti. Nessuna connessione diretta al target. "
        "Utilizzare solo su domini per cui si dispone di autorizzazione esplicita."
    )
    st.markdown("---")

    for key, default in [
        ("scan_count", 0), ("scan_phase", "idle"),
        ("scan_ctx", None), ("scan_log", []), ("scan_domain", ""),
    ]:
        if key not in st.session_state:
            st.session_state[key] = default

    phase = st.session_state.scan_phase

    if phase in ("idle", "final"):
        col_input, col_btn = st.columns([4, 1])
        with col_input:
            domain: str = st.text_input(
                "Dominio target",
                placeholder="es: azienda.it",
                help="Nome a dominio da analizzare (senza http://)",
                label_visibility="collapsed",
                key="domain_input",
            )
        with col_btn:
            analyze_btn = st.button("🔍 Analizza", use_container_width=True, type="primary")
        if st.session_state.scan_count > 0:
            st.caption(f"Analisi questa sessione: {st.session_state.scan_count}/{_MAX_SCANS_PER_SESSION}")

        if analyze_btn:
            if st.session_state.scan_count >= _MAX_SCANS_PER_SESSION:
                st.warning(
                    f"⚠️ Limite di {_MAX_SCANS_PER_SESSION} analisi per sessione raggiunto. "
                    "Ricarica la pagina per continuare."
                )
                st.stop()
            domain_clean = (
                domain.strip().lower()
                .removeprefix("https://")
                .removeprefix("http://")
                .rstrip("/")
            )
            if not domain_clean:
                st.error("❌ Inserisci un nome a dominio prima di procedere.")
                return
            st.session_state.scan_phase = "running"
            st.session_state.scan_ctx = None
            st.session_state.scan_log = []
            st.session_state.scan_domain = domain_clean
            st.session_state.scan_count += 1
            st.rerun()

    if phase == "idle":
        _render_idle_welcome()
        return

    if phase == "running":
        target = st.session_state.scan_domain
        st.markdown(f"**Analisi in corso per:** `{target}`")
        _render_running_phase(config, target)
        return

    if phase == "final":
        ctx = st.session_state.scan_ctx
        if ctx is None:
            st.session_state.scan_phase = "idle"
            st.rerun()
            return
        if st.button("🔄 Nuova Analisi"):
            st.session_state.scan_phase = "idle"
            st.session_state.scan_ctx = None
            st.session_state.scan_domain = ""
            st.rerun()
        _render_final_phase(ctx)


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
