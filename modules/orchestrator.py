"""Multi-round synergistic OSINT orchestrator.

Runs up to 3 rounds of data collection, each feeding into the next:
  Round 1 — basic scans (subdomains, email, network primary IP, dorking)
  Round 2 — synergistic: subdomains→network, network→targeted dorking, email-IP correlation
  Round 3 — LLM entity extraction + follow-up scans on suggested IPs/domains
  Final   — unified LLM report + connection graph
"""

from __future__ import annotations

import json
from dataclasses import asdict

from google import genai
from google.genai import types as genai_types

from modules.censys_client import fetch_censys
from modules.leakix_client import fetch_leakix
from modules.merger import merge_sources
from modules.osint_dorking import search_by_query, search_exposed_documents
from modules.osint_hunter import fetch_emails_for_domain
from modules.osint_leaklookup import check_emails_for_breaches
from modules.osint_subdomains import get_subdomains
from modules.resolver import resolve_target
from modules.zoomeye_client import fetch_zoomeye
from modules.scan_context import (
    EmailBreachCorrelation,
    ExposedService,
    ScanContext,
    SubdomainScanResult,
)

from collections.abc import Callable
from datetime import datetime

LogFn = Callable[[str], None]
ProgressFn = Callable[[float], None]

def _noop_log(msg: str) -> None: pass
def _noop_progress(val: float) -> None: pass
def _ts() -> str: return datetime.now().strftime("%H:%M:%S")

_SENSITIVE_SERVICES = {
    "mongodb", "redis", "elasticsearch", "cassandra", "memcached",
    "couchdb", "rabbitmq", "mysql", "postgresql", "mssql",
    "ftp", "rsync", "vnc", "rdp", "telnet",
}
_ADMIN_PORTS = {8080, 8443, 8888, 9090, 9200, 5601, 15672, 2375, 4848}
_MAX_FOLLOW_UP = 5


# ── Internal helpers ──────────────────────────────────────────────────────────

def _scan_ip(ip: str, config: dict) -> dict:
    """Run all configured network sources against a single IP and merge results."""
    zoomeye_data: dict = {}
    censys_data: dict = {}
    leakix_data: dict = {}
    sources_queried: list[str] = []

    if config.get("zoomeye_key"):
        sources_queried.append("ZoomEye")
        try:
            zoomeye_data = fetch_zoomeye(config["zoomeye_key"], ip)
        except (ValueError, RuntimeError):
            pass

    if config.get("censys_id") and config.get("censys_secret"):
        sources_queried.append("Censys")
        try:
            censys_data = fetch_censys(config["censys_id"], config["censys_secret"], ip)
        except (ValueError, RuntimeError):
            pass

    if config.get("leakix_key"):
        sources_queried.append("LeakIX")
        try:
            leakix_data = fetch_leakix(config["leakix_key"], ip)
        except (ValueError, RuntimeError):
            pass

    return merge_sources(
        zoomeye=zoomeye_data,
        censys=censys_data,
        leakix=leakix_data,
        target_ip=ip,
        sources_queried=sources_queried,
    )


def _extract_exposed_services(primary_host: dict | None, subdomain_results: list[SubdomainScanResult]) -> list[ExposedService]:
    """Identify sensitive/admin services across all scanned hosts."""
    services: list[ExposedService] = []

    hosts_to_check: list[dict] = []
    if primary_host:
        hosts_to_check.append(primary_host)
    for r in subdomain_results:
        if r.merged_host:
            hosts_to_check.append(r.merged_host)

    for host in hosts_to_check:
        ip = host.get("ip", "")
        for port_info in host.get("ports", {}).values():
            svc = (port_info.get("service") or "").lower()
            product = (port_info.get("product") or "").lower()
            port = port_info.get("port", 0)
            leaks = port_info.get("leaks", [])

            is_sensitive = (
                any(s in svc or s in product for s in _SENSITIVE_SERVICES)
                or port in _ADMIN_PORTS
            )
            if is_sensitive:
                services.append(ExposedService(
                    ip=ip,
                    port=port,
                    service_name=svc,
                    product=product,
                    leak_labels=leaks,
                ))

    return services


def _generate_targeted_dork_queries(domain: str, svc: ExposedService) -> list[str]:
    """Build targeted Google dork queries based on a detected exposed service."""
    queries = []
    svc_lower = svc.service_name.lower()
    product_lower = svc.product.lower()

    if "mongo" in svc_lower or "mongo" in product_lower:
        queries.append(f"site:{domain} inurl:mongo")
    if "redis" in svc_lower or "redis" in product_lower:
        queries.append(f"site:{domain} inurl:redis")
    if "elastic" in svc_lower or "elastic" in product_lower or svc.port == 9200:
        queries.append(f"site:{domain} inurl:kibana OR inurl:elasticsearch")
    if "mysql" in svc_lower or "postgre" in svc_lower or "mssql" in svc_lower:
        queries.append(f"site:{domain} filetype:sql")
    if "ftp" in svc_lower:
        queries.append(f"site:{domain} inurl:ftp")
    if svc.port in _ADMIN_PORTS or "admin" in svc_lower:
        queries.append(f"site:{domain} inurl:admin OR inurl:dashboard OR inurl:panel")
    if svc.port == 2375:  # Docker daemon
        queries.append(f"site:{domain} inurl:docker")

    # Generic misconfiguration dork for any sensitive service
    queries.append(f"site:{domain} filetype:env OR filetype:bak OR filetype:conf")

    return list(dict.fromkeys(queries))  # deduplicate preserving order


def _correlate_emails_with_leakix(
    breach_data: dict[str, list[str]],
    primary_host: dict | None,
    subdomain_results: list[SubdomainScanResult],
) -> list[EmailBreachCorrelation]:
    """Cross-match Hunter emails against LeakIX leak labels across all scanned IPs."""
    correlations: list[EmailBreachCorrelation] = []

    # Collect all (ip, leak_labels) pairs
    ip_leaks: list[tuple[str, list[str]]] = []
    if primary_host:
        ip = primary_host.get("ip", "")
        all_leaks = list(primary_host.get("host_leaks", []))
        for port_info in primary_host.get("ports", {}).values():
            all_leaks.extend(port_info.get("leaks", []))
        if all_leaks:
            ip_leaks.append((ip, all_leaks))

    for r in subdomain_results:
        if not r.merged_host or not r.ip:
            continue
        ip = r.ip
        all_leaks = list(r.merged_host.get("host_leaks", []))
        for port_info in r.merged_host.get("ports", {}).values():
            all_leaks.extend(port_info.get("leaks", []))
        if all_leaks:
            ip_leaks.append((ip, all_leaks))

    for email, sources in breach_data.items():
        parts = email.split("@")
        username = parts[0].lower() if parts else ""
        email_domain = parts[1].lower() if len(parts) > 1 else ""

        matched_ips: list[str] = []
        matched_summaries: list[str] = []

        for ip, leaks in ip_leaks:
            for leak in leaks:
                leak_lower = leak.lower()
                if username and username in leak_lower:
                    matched_ips.append(ip)
                    matched_summaries.append(leak)
                elif email_domain and email_domain in leak_lower:
                    matched_ips.append(ip)
                    matched_summaries.append(leak)

        correlations.append(EmailBreachCorrelation(
            email=email,
            breach_sources=sources,
            correlated_ips=list(dict.fromkeys(matched_ips)),
            leakix_summary_matches=matched_summaries,
        ))

    return correlations


def _build_entity_extraction_prompt(ctx: ScanContext) -> str:
    """Prompt for Gemini to extract new IPs/domains worth investigating."""
    host_summaries = []
    if ctx.primary_host:
        host_summaries.append({
            "ip": ctx.primary_ip,
            "org": ctx.primary_host.get("org"),
            "country": ctx.primary_host.get("country"),
            "ports": [p["port"] for p in ctx.primary_host.get("ports", {}).values()],
            "leaks": ctx.primary_host.get("host_leaks", [])[:5],
        })
    for r in ctx.subdomain_results[:10]:
        if r.merged_host:
            host_summaries.append({
                "ip": r.ip,
                "subdomain": r.subdomain,
                "ports": [p["port"] for p in r.merged_host.get("ports", {}).values()],
                "leaks": r.merged_host.get("host_leaks", [])[:3],
            })

    payload = {
        "domain": ctx.domain,
        "emails_found": len(ctx.emails),
        "breach_data_sample": {k: v for k, v in list(ctx.breach_data.items())[:5]},
        "subdomains_count": len(ctx.subdomains),
        "hosts_scanned": host_summaries,
        "correlations": [
            {"email": c.email, "correlated_ips": c.correlated_ips}
            for c in ctx.email_ip_correlations
            if c.correlated_ips
        ],
    }

    return (
        "Sei un analista OSINT. Analizza questi dati di ricognizione passiva e identifica "
        "eventuali IP o domini AGGIUNTIVI che vale la pena investigare (es. CDN correlati, "
        "nameserver, mx record insoliti, IP citati nei banner). "
        "Rispondi SOLO con JSON valido, nessun testo aggiuntivo:\n"
        '{"ips": ["<ip1>", ...], "domains": ["<domain1>", ...]}\n\n'
        f"DATI:\n{json.dumps(payload, ensure_ascii=False, default=str)}"
    )


# ── Public round functions ────────────────────────────────────────────────────

def run_round1(
    ctx: ScanContext,
    log_fn: LogFn = _noop_log,
    progress_fn: ProgressFn = _noop_progress,
) -> ScanContext:
    """Round 1: basic scans — subdomains, dorking, email breach, primary network."""
    config = ctx.config

    # Subdomains (always available — no key needed)
    log_fn(f"[{_ts()}] Round 1 → Subdomain enum: avvio...")
    progress_fn(0.02)
    try:
        ctx.subdomains = get_subdomains(ctx.domain)
    except RuntimeError:
        ctx.subdomains = []
    log_fn(f"[{_ts()}] Round 1 → Subdomains: {len(ctx.subdomains)} trovati")
    progress_fn(0.05)

    # Google Dorking (generic)
    if config.get("serper_key") or config.get("serpapi_key"):
        log_fn(f"[{_ts()}] Round 1 → Dorking generico: avvio...")
        try:
            ctx.exposed_documents = search_exposed_documents(
                ctx.domain,
                config.get("serper_key", ""),
                fallback_key=config.get("serpapi_key", ""),
            )
        except RuntimeError:
            ctx.exposed_documents = []
    log_fn(f"[{_ts()}] Round 1 → Dorking: {len(ctx.exposed_documents)} documenti trovati")
    progress_fn(0.10)

    # Email discovery + breach check
    if config.get("hunter_key"):
        log_fn(f"[{_ts()}] Round 1 → Email Hunter.io: avvio...")
        try:
            ctx.emails = fetch_emails_for_domain(ctx.domain, config["hunter_key"])
        except (ValueError, RuntimeError):
            ctx.emails = []
    log_fn(f"[{_ts()}] Round 1 → Email Hunter.io: {len(ctx.emails)} trovate")
    progress_fn(0.13)

    if ctx.emails and config.get("leaklookup_key"):
        log_fn(f"[{_ts()}] Round 1 → Breach check Leak-Lookup: avvio...")
        try:
            ctx.breach_data = check_emails_for_breaches(ctx.emails, config["leaklookup_key"])
        except ValueError:
            ctx.breach_data = {}
    log_fn(f"[{_ts()}] Round 1 → Breach check: {sum(1 for v in ctx.breach_data.values() if v)} compromesse")
    progress_fn(0.16)

    # Primary IP + network scan
    has_network = (
        bool(config.get("zoomeye_key"))
        or (bool(config.get("censys_id")) and bool(config.get("censys_secret")))
        or bool(config.get("leakix_key"))
    )
    if has_network:
        log_fn(f"[{_ts()}] Round 1 → Network scan IP primario: avvio...")
        try:
            ctx.primary_ip = resolve_target(ctx.domain)
            ctx.primary_host = _scan_ip(ctx.primary_ip, config)
        except ValueError:
            ctx.primary_ip = None
            ctx.primary_host = None
    log_fn(f"[{_ts()}] Round 1 → Network primario: {ctx.primary_ip or 'N/D'}")
    progress_fn(0.20)

    return ctx


def estimate_api_calls(ctx: ScanContext, max_subs: int) -> dict:
    """Estimate API calls before Round 2 starts."""
    config = ctx.config
    n_subs = min(len(ctx.subdomains), max_subs)
    n_sources = sum([
        bool(config.get("zoomeye_key")),
        bool(config.get("censys_id")) and bool(config.get("censys_secret")),
        bool(config.get("leakix_key")),
    ])

    # Pre-compute exposed services to estimate targeted dorks
    exposed = _extract_exposed_services(ctx.primary_host, ctx.subdomain_results)
    n_targeted_dorks = min(len(exposed) * 2, 10)

    return {
        "subdomini_da_scansionare": n_subs,
        "subdomain_network_calls": n_subs * n_sources,
        "zoomeye_calls": n_subs if config.get("zoomeye_key") else 0,
        "censys_calls": n_subs if (config.get("censys_id") and config.get("censys_secret")) else 0,
        "leakix_calls": n_subs if config.get("leakix_key") else 0,
        "targeted_dork_calls": n_targeted_dorks,
        "leaklookup_calls": len(ctx.emails),
        "gemini_calls": 2,
        "total": n_subs * n_sources + n_targeted_dorks + len(ctx.emails) + 2,
    }


def run_round2(
    ctx: ScanContext,
    max_subs: int = 20,
    log_fn: LogFn = _noop_log,
    progress_fn: ProgressFn = _noop_progress,
) -> ScanContext:
    """Round 2: synergistic scans — subdomain network, targeted dorking, email-IP correlation."""
    config = ctx.config

    # 2a: Subdomains → Network scan (IP deduplication)
    already_scanned: set[str] = set()
    if ctx.primary_ip:
        already_scanned.add(ctx.primary_ip)

    subs_to_scan = ctx.subdomains[:max_subs]
    per_sub = 0.40 / max(len(subs_to_scan), 1)

    for i, subdomain in enumerate(subs_to_scan):
        try:
            ip = resolve_target(subdomain)
        except ValueError:
            ctx.subdomain_results.append(SubdomainScanResult(subdomain, None, None))
            log_fn(f"[{_ts()}] Round 2 → {subdomain}: DNS fail, skip")
            progress_fn(0.20 + (i + 1) * per_sub)
            continue

        if ip in already_scanned:
            # Same IP as an already-scanned host — record subdomain but skip scan
            ctx.subdomain_results.append(SubdomainScanResult(subdomain, ip, None))
            log_fn(f"[{_ts()}] Round 2 → {subdomain}: stesso IP ({ip}), skip")
            progress_fn(0.20 + (i + 1) * per_sub)
            continue

        already_scanned.add(ip)
        merged = _scan_ip(ip, config)
        ctx.subdomain_results.append(SubdomainScanResult(subdomain, ip, merged))
        log_fn(f"[{_ts()}] Round 2 → Scansione {subdomain} ({ip}): {len(merged.get('ports', {}))} porte")
        progress_fn(0.20 + (i + 1) * per_sub)

    # 2b: Extract exposed services + targeted dorking
    ctx.exposed_services = _extract_exposed_services(ctx.primary_host, ctx.subdomain_results)
    log_fn(f"[{_ts()}] Round 2 → Servizi esposti: {len(ctx.exposed_services)} rilevati")
    progress_fn(0.62)

    if config.get("serper_key") or config.get("serpapi_key"):
        seen_queries: set[str] = set()
        for svc in ctx.exposed_services[:5]:  # cap to avoid quota exhaustion
            for query in _generate_targeted_dork_queries(ctx.domain, svc):
                if query in seen_queries:
                    continue
                seen_queries.add(query)
                try:
                    results = search_by_query(
                        query,
                        config.get("serper_key", ""),
                        fallback_key=config.get("serpapi_key", ""),
                    )
                    ctx.targeted_dork_results.extend(results)
                    log_fn(f"[{_ts()}] Round 2 → Dorking: '{query[:50]}' → {len(results)} risultati")
                except RuntimeError:
                    pass

    # Deduplicate targeted dork results by URL
    seen_urls: set[str] = set()
    deduped: list[dict] = []
    for doc in ctx.targeted_dork_results:
        if doc.get("url") not in seen_urls:
            seen_urls.add(doc["url"])
            deduped.append(doc)
    ctx.targeted_dork_results = deduped

    # 2c: Email-IP correlation
    ctx.email_ip_correlations = _correlate_emails_with_leakix(
        ctx.breach_data, ctx.primary_host, ctx.subdomain_results
    )
    log_fn(f"[{_ts()}] Round 2 → Correlazioni email-IP: {len(ctx.email_ip_correlations)}")
    progress_fn(0.70)

    return ctx


def run_round3(
    ctx: ScanContext,
    log_fn: LogFn = _noop_log,
    progress_fn: ProgressFn = _noop_progress,
) -> ScanContext:
    """Round 3: LLM entity extraction + follow-up scans on suggested IPs/domains."""
    config = ctx.config
    if not config.get("ai_key"):
        log_fn(f"[{_ts()}] Round 3 → Gemini API Key mancante, skip")
        progress_fn(0.90)
        return ctx

    log_fn(f"[{_ts()}] Round 3 → Gemini entity extraction: avvio...")
    progress_fn(0.72)

    try:
        client = genai.Client(api_key=config["ai_key"])
        prompt = _build_entity_extraction_prompt(ctx)
        response = client.models.generate_content(
            model=config.get("model_name", "gemini-2.5-flash"),
            contents=prompt,
            config=genai_types.GenerateContentConfig(
                temperature=0.1,
                response_mime_type="application/json",
            ),
        )
        raw = response.text.strip()
        # Strip markdown code fences if present
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        suggested = json.loads(raw)
        ctx.llm_suggested_ips = suggested.get("ips", [])[:_MAX_FOLLOW_UP]
        ctx.llm_suggested_domains = suggested.get("domains", [])[:_MAX_FOLLOW_UP]
    except Exception:
        progress_fn(0.90)
        return ctx

    log_fn(f"[{_ts()}] Round 3 → Gemini: {len(ctx.llm_suggested_ips)} IP, {len(ctx.llm_suggested_domains)} domini suggeriti")
    progress_fn(0.78)

    # Scan suggested entities
    already_scanned: set[str] = set()
    if ctx.primary_ip:
        already_scanned.add(ctx.primary_ip)
    for r in ctx.subdomain_results:
        if r.ip:
            already_scanned.add(r.ip)

    followup_idx = 0
    for ip in ctx.llm_suggested_ips:
        if ip in already_scanned:
            continue
        already_scanned.add(ip)
        log_fn(f"[{_ts()}] Round 3 → Scansione IP suggerito: {ip}")
        progress_fn(0.78 + followup_idx * 0.012)
        merged = _scan_ip(ip, config)
        if merged.get("sources_ok"):
            ctx.follow_up_host_results.append(merged)
        followup_idx += 1

    for dom in ctx.llm_suggested_domains:
        try:
            ip = resolve_target(dom)
        except ValueError:
            continue
        if ip in already_scanned:
            continue
        already_scanned.add(ip)
        log_fn(f"[{_ts()}] Round 3 → Scansione dominio suggerito: {dom} ({ip})")
        progress_fn(0.78 + followup_idx * 0.012)
        merged = _scan_ip(ip, config)
        if merged.get("sources_ok"):
            ctx.follow_up_host_results.append(merged)
        followup_idx += 1

    progress_fn(0.90)
    return ctx


def run_final(
    ctx: ScanContext,
    log_fn: LogFn = _noop_log,
    progress_fn: ProgressFn = _noop_progress,
) -> ScanContext:
    """Final round: generate unified LLM report and build graph data."""
    from modules.unified_report import generate_unified_report
    from modules.graph_builder import build_graph_data

    log_fn(f"[{_ts()}] Final → Generazione report unificato Gemini...")
    progress_fn(0.91)

    if ctx.config.get("ai_key"):
        try:
            ctx.unified_report = generate_unified_report(
                ctx,
                api_key=ctx.config["ai_key"],
                model_name=ctx.config.get("model_name", "gemini-2.5-flash"),
            )
        except RuntimeError:
            ctx.unified_report = None
    log_fn(f"[{_ts()}] Final → Report generato ({len(ctx.unified_report or '')} chars)")
    progress_fn(0.96)

    ctx.graph_data = build_graph_data(ctx)
    n_nodes = len((ctx.graph_data or {}).get("nodes", []))
    n_edges = len((ctx.graph_data or {}).get("edges", []))
    log_fn(f"[{_ts()}] Final → Grafo: {n_nodes} nodi, {n_edges} archi")
    progress_fn(1.0)

    return ctx
