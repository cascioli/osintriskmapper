# OSINT Risk Mapper
### Attack Surface Management per PMI

> Tool passivo alimentato dall'AI per mappare i rischi delle identità digitali e degli asset nascosti delle aziende — senza toccare un singolo pacchetto di rete.

![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.35%2B-FF4B4B?logo=streamlit&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-green)
![OSINT: Passive Only](https://img.shields.io/badge/OSINT-Passive%20Only-orange)

---

## Perché l'ho costruito

Lavorando nel contesto del tessuto economico locale — PMI agricole, aziende logistiche e piccoli studi professionali della provincia di Foggia e della Capitanata — ho notato un pattern ricorrente: queste realtà **non sono vulnerabili per via di infrastrutture complesse**, ma per motivi molto più banali e sottovalutati.

Credenziali aziendali finite in data breach, sottodomini abbandonati che espongono pannelli admin, documenti Excel con listini prezzi indicizzati da Google. Nessuno lo sa. Nessuno li cerca. Nessuno li trova — finché non li trova qualcun altro.

**OSINT Risk Mapper** nasce per dare a un professionista della sicurezza (o a un'azienda curiosa della propria esposizione) uno strumento di ricognizione passiva completo, che aggreghi più fonti e traduca i dati tecnici in un report di rischio comprensibile anche da chi non legge Nmap output per hobby.

---

## Disclaimer Etico

> [!WARNING]
> **Questo tool è progettato esclusivamente per uso etico, difensivo e preventivo.**
>
> - Utilizza **esclusivamente tecniche passive** (OSINT) tramite API pubbliche e database di intelligence esistenti.
> - **Non esegue scansioni attive** di rete, non invia pacchetti ai target, non sfrutta vulnerabilità.
> - **Non scarica, accede o modifica** dati o sistemi di terze parti.
> - Va utilizzato **solo su domini di propria proprietà** o per i quali si dispone di **autorizzazione scritta esplicita**.
>
> L'uso non autorizzato può configurare reati ai sensi degli artt. 615-ter e seguenti del Codice Penale italiano e del Computer Fraud and Abuse Act (CFAA). L'autore declina ogni responsabilità per usi impropri.

---

## Screenshot

<!-- Aggiungi uno screenshot della dashboard: docs/screenshot.png -->
> *Aggiungi uno screenshot della dashboard Streamlit (`docs/screenshot.png`) per mostrare le 4 tab, le tabelle colorate e i report AI.*

```
Esempio di ciò che vedrai:
┌─────────────────────────────────────────────────────────┐
│  OSINT Risk Mapper  │ Sidebar: API Keys + AI Provider   │
├─────────────┬───────┴──────────┬───────────┬────────────┤
│ Email Breach│ Network Intel    │ Sottodomini│  Dorking   │
│ 🔴 3 pwned  │ IP: 1.2.3.4     │ 12 trovati │ 5 doc exp. │
│ 🟢 7 clean  │ 🔴 Port 22 open │            │ .xls .pdf  │
│             │ ⚠️  CVE-2023-xx  │            │            │
│ [AI Report] │ [AI Report]     │            │            │
└─────────────┴─────────────────┴────────────┴────────────┘
```

---

## Funzionalità

Il tool analizza un dominio aziendale su quattro livelli di sicurezza distinti:

### 🔐 Analisi Breach Email — Identità Compromesse
Scopre le email aziendali associate al dominio tramite **Hunter.io**, poi le verifica contro i database di data breach via **Leak-Lookup**. Ogni email viene classificata come compromessa (🔴) o pulita (🟢), con indicazione delle fonti di breach.

### 🌐 Enumerazione Sottodomini — Asset Nascosti
Interroga i **Certificate Transparency Logs** tramite **crt.sh** per enumerare passivamente tutti i sottodomini registrati nel tempo. Rivela sottodomini dimenticati (`staging.`, `dev.`, `old.`, `vpn.`, `admin.`) che possono rappresentare vettori d'attacco non monitorati.

### 🔍 Google Dorking — Data Leakage Preventivo
Sfrutta la **Google Custom Search API** per cercare documenti sensibili pubblicamente indicizzati: file `.pdf`, `.doc`, `.xls`, `.xlsx`, `.sql`, `.env`, `.bak`. Identifica ciò che non dovrebbe essere trovabile — ma lo è.

### 🖥️ Network Intelligence — Superfice d'Attacco Esposta
Risolve il dominio in IP e interroga in parallelo tre fonti di threat intelligence passiva:
- **ZoomEye** — host e servizi esposti su internet
- **Censys** — enumerazione porte e banner (Autonomous System, country)
- **LeakIX** — eventi di leak e configurazioni esposte (Git, DB, credenziali)

I risultati vengono deduplicati per porta e unificati in una vista consolidata con CVE, leak e fonti per ogni servizio.

### 🤖 AI Threat Reporting — Report Automatizzato
Un LLM (configurabile tra **Gemini 2.5 Flash**, **OpenAI** o **Ollama locale**) analizza i dati raccolti e genera un report strutturato in linguaggio naturale: rischio complessivo, priorità di remediation, pattern critici identificati.

---

## Architettura

```
osintriskmapper/
├── app.py                   # Entry point Streamlit — UI e orchestrazione pipeline
├── modules/
│   ├── osint_hunter.py      # Hunter.io API — email discovery
│   ├── osint_leaklookup.py  # Leak-Lookup API — breach check
│   ├── osint_subdomains.py  # crt.sh — Certificate Transparency
│   ├── osint_dorking.py     # Google Custom Search — sensitive file discovery
│   ├── zoomeye_client.py    # ZoomEye API — host intelligence
│   ├── censys_client.py     # Censys v2 API — port/service enumeration
│   ├── leakix_client.py     # LeakIX API — leak events
│   ├── merger.py            # Deduplicazione e consolidamento dati multi-fonte
│   ├── resolver.py          # DNS resolution domain → IP
│   ├── ai_analyzer.py       # Report AI su breach email (Gemini/OpenAI)
│   ├── llm_client.py        # Report AI su network intel (Gemini/OpenAI)
│   └── ui.py                # Componenti UI Streamlit riutilizzabili
└── utils/
    └── config.py            # Caricamento sicuro delle API key da .env
```

**Principi di design:**
- Ogni modulo OSINT è indipendente e testabile in isolamento
- Il `merger.py` normalizza dati eterogenei da 3 fonti in una struttura unificata (chiave: porta TCP/UDP)
- Le API key non vengono mai hardcodate — caricate da `.env` tramite `python-dotenv` e mai incluse nel repository

---

## API Key Necessarie

Alcune integrazioni richiedono una chiave API. La maggior parte offre un tier gratuito sufficiente per uso personale/professionale.

| Variabile | Servizio | Free Tier | Dove ottenerla |
|-----------|----------|-----------|----------------|
| `HUNTER_API_KEY` | Hunter.io | Sì (25 ricerche/mese) | [hunter.io](https://hunter.io) |
| `LEAKLOOKUP_API_KEY` | Leak-Lookup | Sì | [leak-lookup.com](https://leak-lookup.com) |
| `ZOOMEYE_API_KEY` | ZoomEye | Parziale | [zoomeye.org](https://www.zoomeye.org) |
| `CENSYS_API_ID` + `CENSYS_API_SECRET` | Censys | Sì | [censys.io](https://censys.io) |
| `LEAKIX_API_KEY` | LeakIX | Sì | [leakix.net](https://leakix.net) |
| `GEMINI_API_KEY` | Google AI Studio | Sì (Gemini 2.5 Flash) | [aistudio.google.com](https://aistudio.google.com) |
| `OPENAI_API_KEY` | OpenAI | No (paid) | [platform.openai.com](https://platform.openai.com) |
| `GOOGLE_SEARCH_API_KEY` + `GOOGLE_CX_ID` | Google Custom Search | 100 query/giorno | [console.cloud.google.com](https://console.cloud.google.com) |

> **Nota:** Il modulo di enumerazione sottodomini (crt.sh) è completamente gratuito e non richiede alcuna API key.
>
> Per il dorking con Google Custom Search, è necessario creare sia una chiave API nel progetto Google Cloud che un **Programmable Search Engine (CX ID)** configurato per ricercare l'intero web.

---

## Installazione

**Prerequisiti:** Python 3.10 o superiore, `git`.

```bash
# 1. Clona il repository
git clone https://github.com/[username]/osintriskmapper.git
cd osintriskmapper

# 2. Crea e attiva il virtual environment
python -m venv venv
source venv/bin/activate        # Linux / macOS
# venv\Scripts\activate         # Windows

# 3. Installa le dipendenze
pip install -r requirements.txt

# 4. Configura le API key
cp .env.example .env
```

Apri il file `.env` con un editor di testo e inserisci le chiavi API che hai ottenuto:

```env
HUNTER_API_KEY=la_tua_chiave_hunter
LEAKLOOKUP_API_KEY=la_tua_chiave_leaklookup
GEMINI_API_KEY=la_tua_chiave_gemini
# ... e così via per le altre
```

> Le chiavi lasciate vuote disabiliteranno automaticamente il modulo corrispondente senza causare errori — puoi iniziare anche con solo alcune chiavi.

---

## Utilizzo

```bash
streamlit run app.py
```

Il browser si aprirà automaticamente su `http://localhost:8501`.

1. **Configura il provider AI** nel pannello laterale (Gemini, OpenAI, o Ollama locale)
2. **Inserisci il dominio** da analizzare (es. `azienda.it`)
3. **Naviga tra le 4 tab** per eseguire le diverse pipeline di analisi
4. **Leggi il report AI** generato automaticamente per ogni pipeline

---

## Stack Tecnologico

| Componente | Tecnologia |
|------------|------------|
| UI / Dashboard | [Streamlit](https://streamlit.io) |
| Data manipulation | [Pandas](https://pandas.pydata.org) |
| AI (cloud) | Google Gemini 2.5 Flash / OpenAI API |
| AI (locale) | [Ollama](https://ollama.ai) (via endpoint OpenAI-compatible) |
| HTTP client | [Requests](https://requests.readthedocs.io) |
| Config management | [python-dotenv](https://pypi.org/project/python-dotenv/) |

---

## Licenza

MIT — libero di usare, modificare e distribuire con attribuzione.
