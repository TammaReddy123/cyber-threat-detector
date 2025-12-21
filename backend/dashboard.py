import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import sqlite3
import os
import tldextract
import time
from streamlit_autorefresh import st_autorefresh
from predict import URLThreatModel
from risk_scoring import compute_risk_score

# ==========================================================
# CONFIG
# ==========================================================
st.set_page_config(
    page_title="AI Threat Intelligence",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==========================================================
# DATABASE
# ==========================================================
DB_PATH = os.path.join(os.path.dirname(__file__), "threat_logs.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            prediction TEXT,
            confidence REAL,
            risk_score REAL,
            severity TEXT,
            vt_malicious INTEGER,
            vt_suspicious INTEGER,
            country TEXT,
            timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_log(url, prediction, confidence, risk_score, severity,
             vt_mal, vt_susp, country):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO logs
        VALUES (NULL,?,?,?,?,?,?,?, ?,?)
    """, (
        url, prediction, confidence,
        risk_score, severity,
        vt_mal, vt_susp,
        country, datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    conn.commit()
    conn.close()

def get_logs():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.cursor().execute(
        "SELECT * FROM logs ORDER BY id DESC"
    ).fetchall()
    conn.close()
    return rows

init_db()

# ==========================================================
# MODEL
# ==========================================================
@st.cache_resource(show_spinner=False)
def load_model():
    return URLThreatModel()

# ==========================================================
# THEME + FX
# ==========================================================
def set_edex_theme():
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');

    html, body, .stApp {
        background: radial-gradient(circle at center, #020617, #000000);
        color: #00ff88;
        font-family: 'Share Tech Mono', monospace;
    }

    section[data-testid="stSidebar"] {
        width: 200px !important;
        background: #020617;
        border-right: 1px solid #00ff8855;
    }

    .metric-card {
        background:#020617;
        border:1px solid #00ff8855;
        border-radius:12px;
        padding:14px;
        text-align:center;
        box-shadow:0 0 16px #00ff8822;
    }

    .edex-terminal {
        background:#020617;
        border:1px solid #00ff8855;
        border-radius:12px;
        padding:14px;
        font-size:13px;
        box-shadow:0 0 18px #00ff8822;
    }

    .neon {
        text-shadow:0 0 12px #00ff88;
    }

    .matrix {
        position:fixed;
        inset:0;
        background-image:
          linear-gradient(rgba(0,255,136,.05) 1px, transparent 1px),
          linear-gradient(90deg, rgba(0,255,136,.05) 1px, transparent 1px);
        background-size:20px 20px;
        pointer-events:none;
        z-index:-1;
    }

    .radar {
        position:fixed;
        top:50%;
        left:50%;
        width:600px;
        height:600px;
        border-radius:50%;
        background:conic-gradient(
            from 0deg,
            rgba(0,255,136,0),
            rgba(0,255,136,.35),
            rgba(0,255,136,0)
        );
        animation:spin 4s linear infinite;
        transform:translate(-50%,-50%);
        opacity:.25;
        pointer-events:none;
    }

    @keyframes spin {
        to { transform:translate(-50%,-50%) rotate(360deg); }
    }
    </style>
    <div class="matrix"></div>
    """, unsafe_allow_html=True)

# ==========================================================
# HELPERS
# ==========================================================
def extract_country(url):
    ext = tldextract.extract(url)
    suffix = ext.suffix.lower()
    mapping = {
        "in":"India","gov.in":"India","co.in":"India",
        "uk":"United Kingdom","co.uk":"United Kingdom",
        "us":"United States","au":"Australia","ca":"Canada",
        "de":"Germany","fr":"France","jp":"Japan","cn":"China","br":"Brazil"
    }
    return mapping.get(suffix, mapping.get(suffix.split(".")[-1]))

def edex_terminal():
    st.markdown("""
    <div class="edex-terminal neon">
        PS C:\\CyberThreat&gt;<br>
        [BOOT] Neural core online<br>
        [OK] Threat signatures loaded<br>
        [OK] VT channel secured<br>
        STATUS: ONLINE
    </div>
    """, unsafe_allow_html=True)

# ==========================================================
# SIDEBAR
# ==========================================================
def sidebar():
    st.sidebar.markdown("## 📌 NAVIGATION")
    page = st.sidebar.selectbox("", [
        "URL Scanner", "Analytics Dashboard", "Global Threat Map"
    ])
    st.sidebar.markdown("---")
    st.sidebar.markdown("## 📁 HISTORY")

    for log in get_logs()[:4]:
        st.sidebar.markdown(
            f"**{log[1][:28]}**  \nRisk: {log[4]} ({log[5]})"
        )

    return page

# ==========================================================
# URL SCANNER
# ==========================================================
def show_scanner():
    st.markdown("<h2 class='neon'>🛡️ URL Risk Analyzer</h2>", unsafe_allow_html=True)

    col1, col2 = st.columns([1.2,2])

    with col1:
        edex_terminal()

    with col2:
        url = st.text_input("Enter URL", placeholder="https://example.com")
        scan = st.button("SCAN")

        if scan and url:
            with st.spinner("Analyzing…"):
                model = load_model()
                pred, conf, probs = model.predict_single(url)
                risk = compute_risk_score(url, pred, probs)
                country = extract_country(url)

                save_log(
                    url, pred, conf*100,
                    risk["risk_score"], risk["severity"],
                    risk["vt"]["malicious"],
                    risk["vt"]["suspicious"], country
                )

                c1,c2,c3 = st.columns(3)
                c1.markdown(f"<div class='metric-card'>Prediction<br><b>{pred}</b></div>", unsafe_allow_html=True)
                c2.markdown(f"<div class='metric-card'>Confidence<br><b>{conf*100:.1f}%</b></div>", unsafe_allow_html=True)
                c3.markdown(f"<div class='metric-card'>Risk<br><b>{risk['risk_score']}</b></div>", unsafe_allow_html=True)

# ==========================================================
# ANALYTICS
# ==========================================================
def show_analytics():
    st.markdown("<h1 class='neon'>📊 Threat Analytics</h1>", unsafe_allow_html=True)

    df = pd.DataFrame(get_logs(), columns=[
        "id","url","prediction","confidence","risk_score",
        "severity","vt_mal","vt_susp","country","timestamp"
    ])
    if df.empty:
        st.info("No data yet.")
        return

    col1,col2,col3,col4 = st.columns(4)
    col1.metric("SCANS", len(df))
    col2.metric("AVG RISK", f"{df['risk_score'].mean():.1f}")
    col3.metric("HIGH+", (df['severity'].isin(["High","Critical"])).sum())
    col4.metric("COUNTRIES", df["country"].nunique())

    fig = px.pie(df, names="prediction", hole=0.5)
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="#00ff88")
    st.plotly_chart(fig, use_container_width=True)

# ==========================================================
# GLOBAL MAP (ROTATING)
# ==========================================================
def show_global_map():
    from streamlit_autorefresh import st_autorefresh
    import numpy as np

    # Refresh every 200ms (smooth but not heavy)
    st_autorefresh(interval=200, key="globe_refresh")

    st.markdown("<h1 class='neon'>🌍 GLOBAL THREAT MAP</h1>", unsafe_allow_html=True)

    logs = get_logs()
    if not logs:
        st.info("No scan data available.")
        return

    df = pd.DataFrame(logs, columns=[
        "id","url","prediction","confidence","risk_score",
        "severity","vt_mal","vt_susp","country","timestamp"
    ])

    df = df.dropna(subset=["country"])
    if df.empty:
        st.info("No geo data yet.")
        return

    counts = df["country"].value_counts().reset_index()
    counts.columns = ["country", "count"]

    # ======================
    # ROTATION STATE
    # ======================
    if "rot" not in st.session_state:
        st.session_state.rot = 0

    st.session_state.rot = (st.session_state.rot + 0.6) % 360  # 👈 slow & smooth

    # ======================
    # GLOBE
    # ======================
    fig = px.choropleth(
        counts,
        locations="country",
        locationmode="country names",
        color="count",
        color_continuous_scale="Greens"
    )

    fig.update_geos(
        projection_type="orthographic",
        projection_rotation_lon=st.session_state.rot,
        showland=True,
        landcolor="#020617",
        showocean=True,
        oceancolor="#000000",
        showcountries=True,
        countrycolor="rgb(0,255,136)",
        showcoastlines=False,
        showframe=False,
        bgcolor="rgba(0,0,0,0)"
    )

    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        geo=dict(bgcolor="rgba(0,0,0,0)"),
        height=650,
        margin=dict(l=0, r=0, t=0, b=0),
        font_color="#00ff88"
    )

    st.plotly_chart(fig, use_container_width=True)

# ==========================================================
# MAIN
# ==========================================================
def main():
    set_edex_theme()
    page = sidebar()

    if page == "URL Scanner":
        show_scanner()
    elif page == "Analytics Dashboard":
        show_analytics()
    else:
        show_global_map()

if __name__ == "__main__":
    main()
 