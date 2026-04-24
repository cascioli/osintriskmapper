"""
OSINT Risk Mapper — entry point.

Passive Threat Intelligence tool: aggregates data from ZoomEye, Censys, and
LeakIX, deduplicates findings, and generates an AI-powered security risk report.
No active scanning is performed — all data comes from pre-indexed public sources.

Usage:
    streamlit run app.py
"""

import streamlit as st

from modules.censys_client import fetch_censys
from modules.leakix_client import fetch_leakix
from modules.llm_client import analyze_with_gemini, analyze_with_openai_compat
from modules.merger import merge_sources, to_dataframe
from modules.resolver import resolve_target
from modules.zoomeye_client import fetch_zoomeye
from modules.ui import (
    render_ai_report,
    render_consolidated_table,
    render_ethical_banner,
    render_host_metrics,
    render_sidebar,
)


def main() -> None:
    st.set_page_config(
        page_title="OSINT Risk Mapper",
        page_icon="🔍",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    render_ethical_banner()
    config = render_sidebar()

    st.title("🔍 OSINT Risk Mapper")
    st.caption(
        "Threat Intelligence passiva · Aggregazione ZoomEye + Censys + LeakIX + AI"
    )
    st.markdown("---")

    # ── Target input ──────────────────────────────────────────────────────────
    col_input, col_btn = st.columns([4, 1])
    with col_input:
        target: str = st.text_input(
            "Target",
            placeholder="Es: 8.8.8.8 oppure example.com",
            help="Inserisci un indirizzo IPv4 o un nome di dominio da analizzare",
            label_visibility="collapsed",
        )
    with col_btn:
        analyze_btn = st.button(
            "🔍 Analizza",
            use_container_width=True,
            type="primary",
        )

    if not analyze_btn:
        st.markdown(
            """
            #### Come usare OSINT Risk Mapper
            1. Configura almeno **una** chiave API OSINT nella sidebar
               (ZoomEye, Censys, o LeakIX).
            2. Inserisci la **LLM API Key** per la generazione del report AI.
            3. Digita un **indirizzo IP** o un **dominio** nel campo sopra.
            4. Clicca **Analizza** per avviare la raccolta dati passiva.

            > **Nota:** Questo tool non effettua *nessuna* connessione diretta al target.
            > Tutti i dati provengono dagli indici pubblici di ZoomEye, Censys e LeakIX.
            """
        )
        return

    # ── Input validation ──────────────────────────────────────────────────────
    if not target.strip():
        st.error("❌ Inserisci un indirizzo IP o un dominio prima di procedere.")
        return

    has_osint_key = (
        bool(config["zoomeye_key"])
        or (bool(config["censys_id"]) and bool(config["censys_secret"]))
        or bool(config["leakix_key"])
    )
    if not has_osint_key:
        st.error(
            "❌ Configura almeno una fonte OSINT nella sidebar "
            "(ZoomEye, Censys ID + Secret, oppure LeakIX)."
        )
        return

    if not config["llm_key"]:
        st.error("❌ LLM API Key mancante. Inseriscila nella sidebar.")
        return

    # ── Analysis pipeline ─────────────────────────────────────────────────────
    try:
        # Step 1 — DNS resolution
        with st.spinner(f"🌐 Risoluzione target '{target}'…"):
            ip = resolve_target(target)

        if ip != target.strip():
            st.info(f"🌐 Dominio **{target}** risolto in: `{ip}`")

        # Step 2 — Fetch from each enabled source; errors are non-fatal
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
                        st.info("ℹ️ ZoomEye: nessun dato indicizzato per questo host.")
                except ValueError as exc:
                    st.error(f"❌ {exc}")
                except RuntimeError as exc:
                    st.warning(f"⚠️ {exc}")
                except Exception as exc:
                    st.warning(f"⚠️ ZoomEye: errore inatteso ({type(exc).__name__}): {exc}")

        if config["censys_id"] and config["censys_secret"]:
            sources_queried.append("Censys")
            with st.spinner("🔍 Interrogazione Censys…"):
                try:
                    censys_data = fetch_censys(
                        config["censys_id"], config["censys_secret"], ip
                    )
                    if not censys_data:
                        st.info("ℹ️ Censys: nessun dato indicizzato per questo host.")
                except ValueError as exc:
                    st.error(f"❌ {exc}")
                except RuntimeError as exc:
                    st.warning(f"⚠️ {exc}")
                except Exception as exc:
                    st.warning(f"⚠️ Censys: errore inatteso ({type(exc).__name__}): {exc}")

        if config["leakix_key"]:
            sources_queried.append("LeakIX")
            with st.spinner("🔍 Interrogazione LeakIX…"):
                try:
                    leakix_data = fetch_leakix(config["leakix_key"], ip)
                    if not leakix_data:
                        st.info("ℹ️ LeakIX: nessun evento rilevato per questo host.")
                except ValueError as exc:
                    st.error(f"❌ {exc}")
                except RuntimeError as exc:
                    st.warning(f"⚠️ {exc}")
                except Exception as exc:
                    st.warning(f"⚠️ LeakIX: errore inatteso ({type(exc).__name__}): {exc}")

        # Step 3 — Merge and deduplicate
        merged = merge_sources(
            zoomeye=zoomeye_data,
            censys=censys_data,
            leakix=leakix_data,
            target_ip=ip,
            sources_queried=sources_queried,
        )

        if not merged["sources_ok"]:
            st.error(
                "❌ Nessuna fonte ha restituito dati per questo host. "
                "Verifica le chiavi API e riprova."
            )
            return

        # Step 4 — LLM analysis
        with st.spinner("🤖 Analisi AI in corso…"):
            if config["llm_provider"] == "gemini":
                report = analyze_with_gemini(
                    api_key=config["llm_key"],
                    model_name=config["gemini_model"],
                    data=merged,
                )
            else:
                report = analyze_with_openai_compat(
                    api_key=config["llm_key"],
                    base_url=config["openai_base_url"],
                    model=config["openai_model"],
                    data=merged,
                )

        # ── Results layout ────────────────────────────────────────────────────
        sources_label = ", ".join(merged["sources_ok"])
        st.success(
            f"✅ Analisi completata per **{ip}** · "
            f"Fonti: {sources_label} · "
            f"Org: {merged.get('org') or 'N/D'}"
        )
        st.markdown("---")

        render_host_metrics(merged)
        st.markdown("---")

        render_ai_report(report)
        st.markdown("---")

        st.subheader("🗂️ Tabella Consolidata — Porte, Servizi e Vulnerabilità")
        df = to_dataframe(merged)
        render_consolidated_table(df)

        # Raw merged data — hidden by default
        with st.expander("📦 Dati Aggregati Grezzi (debug)"):
            debug_data = {
                k: (list(v.values()) if k == "ports" else v)
                for k, v in merged.items()
            }
            st.json(debug_data)

    except ValueError as exc:
        st.error(f"❌ Errore di risoluzione DNS: {exc}")

    except Exception as exc:  # noqa: BLE001
        st.error(f"❌ Errore imprevisto: {exc}")


if __name__ == "__main__":
    main()
