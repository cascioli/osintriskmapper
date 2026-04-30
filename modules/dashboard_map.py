"""Heatmap territoriale del rischio cyber per la Provincia di Foggia.

Dati simulati per portfolio — aggregati a livello comunale (GDPR-compliant).
"""

from pathlib import Path
from typing import Optional

import pandas as pd
import plotly.express as px
import requests
import streamlit as st
from plotly.graph_objects import Figure

_GEOJSON_URL = (
    "https://raw.githubusercontent.com/openpolis/geojson-italy"
    "/master/geojson/limits_IT_municipalities.geojson"
)
_FOGGIA_PROV_CODE = 71
_CSV_PATH = Path(__file__).parent.parent / "assets" / "province_data.csv"

_FALLBACK_DATA = [
    {"Comune": "Foggia",       "PMI_Analizzate": 47, "Vulnerabilita_Critiche": 23, "Rischio_Medio": 8.2},
    {"Comune": "Cerignola",    "PMI_Analizzate": 31, "Vulnerabilita_Critiche": 11, "Rischio_Medio": 6.5},
    {"Comune": "Manfredonia",  "PMI_Analizzate": 22, "Vulnerabilita_Critiche":  9, "Rischio_Medio": 6.1},
    {"Comune": "San Severo",   "PMI_Analizzate": 19, "Vulnerabilita_Critiche": 14, "Rischio_Medio": 7.3},
    {"Comune": "Lucera",       "PMI_Analizzate": 12, "Vulnerabilita_Critiche":  4, "Rischio_Medio": 4.8},
]


def load_province_data() -> pd.DataFrame:
    """Legge assets/province_data.csv. Fallback ai dati hardcoded se file assente."""
    if _CSV_PATH.exists():
        return pd.read_csv(_CSV_PATH)
    return pd.DataFrame(_FALLBACK_DATA)


# Alias per retrocompatibilità con chiamate esistenti in app.py
generate_mock_province_data = load_province_data


@st.cache_data(ttl=86400)
def _fetch_foggia_geojson() -> Optional[dict]:
    """Download e filtra GeoJSON comuni italiani per Provincia di Foggia (ISTAT 71).

    Cachea per 24h per evitare download ripetuti (~40 MB).
    Restituisce None su qualsiasi errore di rete o parsing.
    """
    try:
        resp = requests.get(_GEOJSON_URL, timeout=30)
        resp.raise_for_status()
        full = resp.json()
    except Exception:
        return None

    features = [
        f for f in full.get("features", [])
        if f.get("properties", {}).get("prov_istat_code_num") == _FOGGIA_PROV_CODE
    ]

    if not features:
        return None

    return {"type": "FeatureCollection", "features": features}


def render_heatmap() -> Optional[Figure]:
    """Genera la mappa coropletica del rischio cyber — Provincia di Foggia.

    Restituisce None se il GeoJSON remoto non è disponibile.
    """
    df = generate_mock_province_data()
    geojson = _fetch_foggia_geojson()

    if geojson is None:
        return None

    # Filtra GeoJSON ai soli comuni presenti nel DataFrame — evita
    # che Plotly renderizzi tutti i 61 comuni della provincia come blob unico.
    comuni_set = set(df["Comune"])
    geojson_filtered = {
        "type": "FeatureCollection",
        "features": [
            f for f in geojson["features"]
            if f.get("properties", {}).get("name") in comuni_set
        ],
    }

    fig = px.choropleth_mapbox(
        df,
        geojson=geojson_filtered,
        locations="Comune",
        featureidkey="properties.name",
        color="Rischio_Medio",
        color_continuous_scale=[
            [0.0, "#00d4ff"],
            [0.5, "#7b00ff"],
            [1.0, "#ff006e"],
        ],
        range_color=(0, 10),
        mapbox_style="carto-darkmatter",
        center={"lat": 41.46, "lon": 15.54},
        zoom=8,
        opacity=0.8,
        hover_name="Comune",
        hover_data={
            "Comune": False,
            "PMI_Analizzate": True,
            "Vulnerabilita_Critiche": True,
            "Rischio_Medio": True,
        },
        labels={
            "Rischio_Medio": "RISCHIO (0-10)",
            "PMI_Analizzate": "PMI Analizzate",
            "Vulnerabilita_Critiche": "Vulnerabilità Critiche",
        },
    )
    fig.update_traces(
        marker_line_color="#00d4ff",
        marker_line_width=2,
    )
    fig.update_layout(
        paper_bgcolor="#050d1a",
        plot_bgcolor="#050d1a",
        font=dict(color="#00d4ff", family="monospace"),
        margin={"r": 0, "t": 30, "l": 0, "b": 0},
        height=520,
        coloraxis_colorbar=dict(
            title="RISCHIO",
            tickvals=[0, 2, 4, 6, 8, 10],
            tickfont=dict(color="#00d4ff", family="monospace"),
            title_font=dict(color="#00d4ff", family="monospace"),
            bgcolor="#050d1a",
            bordercolor="#00d4ff",
            borderwidth=1,
            outlinecolor="#00d4ff",
        ),
    )
    return fig
