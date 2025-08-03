# threat_dash.py

import os
import uuid
import bcrypt
import threading
import pandas as pd
from datetime import datetime, timedelta
import altair as alt
import streamlit as st

from datetime import datetime
from streamlit_cookies_controller import CookieController

from network_monitor import start_monitor  # your existing IDS code



# ── 6) PAGE CONFIG (always first Streamlit call) :contentReference[oaicite:7]{index=7}
st.set_page_config(page_title="Threat Dashboard", layout="wide")

# ── 1) PRE-COMPUTED BCRYPT HASHES FOR USERS ────────────────────────────────────
USER_HASHES = {
    "alice": "$2b$12$I9klho0iylOA2ailoLHDI.SHlxhsbuuw7zLHio1L4iUxlFLb81asi",
    "bob": "$2b$12$KZxIexTGB9ZYf/BKr/UgMuDpWAO/SY.BL7jAbw.jbSngGCaaHtS2.",
    "carol": "$2b$12$kq7LzXXINtlwiqXzKyZPyOxC7/JbpvBHbbCP85BIeg95IzgoDOmn6",
}
# ── 2) IN-MEMORY STORE FOR ACTIVE SESSIONS ─────────────────────────────────────
#    Maps session_token → username. In production, replace with a database.
ACTIVE_SESSIONS = {}

# ── 4) COOKIES CONTROLLER SETUP ────────────────────────────────────────────────
cookies = CookieController()

session_token = cookies.get(name="session_token")

# ── 3) SESSION STATE INITIALIZATION ───────────────────────────────────────────
if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False
    st.session_state["username"]  = ""
    st.session_state["monitor_started"] = False


# ── 5) CHECK FOR EXISTING SESSION COOKIE ON EVERY PAGE LOAD ────────────────────
# If the client has a cookie named "session_token", verify it's in ACTIVE_SESSIONS.
  # returns None or string
print(session_token)    
if session_token and (session_token in ACTIVE_SESSIONS):
    # Valid cookie → user is already logged in
    st.session_state["logged_in"] = True
    st.session_state["username"]  = ACTIVE_SESSIONS[session_token]


# ── 7) LOGIN FORM ───────────────────────────────────────────────────────────────
def show_login_form():
    """
    Renders a login form. If credentials are correct, generate a new session token,
    store it in ACTIVE_SESSIONS, set a cookie on the client, and switch to dashboard.
    """
    st.title("🔐 Login to Threat Dashboard")

    uname = st.text_input("Username")
    pwd   = st.text_input("Password", type="password")
    submitted = st.button("Login")

    if submitted:
        # 7a) Check if username exists:
        if uname not in USER_HASHES:
            st.error("❌ Unknown username")
            return

        # 7b) Verify password:
        hashed = USER_HASHES[uname].encode("utf-8")
        if bcrypt.checkpw(pwd.encode("utf-8"), hashed):
            # 7c) Password correct → create a new session token
            new_token = str(uuid.uuid4())
            ACTIVE_SESSIONS[new_token] = uname

            # 7d) Set cookie on client: name="session_token", value=new_token

            expires = datetime.now() + timedelta(days=1)

            #     Expires in 1 day (86_400 seconds). “secure” ensures HTTPS only.
            cookies.set(
                name="session_token",
                value=new_token,
                expires=expires,      # 1 day
                secure=True,
            )
            st.write(st.session_state)

            # 7e) Update session_state so we render the dashboard right away
            st.session_state["logged_in"] = True
            st.session_state["username"]  = uname
            st.rerun()              # ✅ Use st.rerun() instead :contentReference[oaicite:12]{index=12}
        else:
            st.error("❌ Incorrect password")

# ── 8) DASHBOARD VIEW ───────────────────────────────────────────────────────────
def show_dashboard():
    st.sidebar.success(f"Logged in as: {st.session_state['username']}")

    if st.sidebar.button("Logout"):
        token = cookies.get("session_token")
        if token in ACTIVE_SESSIONS:
            del ACTIVE_SESSIONS[token]
        cookies.remove("session_token")
        st.session_state["logged_in"] = False
        st.session_state["username"]  = ""
        st.session_state["monitor_started"] = False
        st.rerun()

    st.title("🔒 Threat Analysis Dashboard")
    st.markdown("Below is a real-time view of IDS alerts.")

    # ── Add a manual “Refresh Data” button ─────────────────────────────
    if st.button("🔄 Refresh Data"):
        # Option A: Clear the cache so load_data() reads the CSV again
        st.cache_data.clear()
        # Option B: Or simply rerun the script (causing load_data to re-run)
        st.rerun()

    # ── Continue with starting the IDS monitor, if not already started ──
    if not st.session_state["monitor_started"]:
        def run_ids():
            # Start real network monitoring on interface en0
            start_monitor(interface="en0", simulate=False)
        thread = threading.Thread(target=run_ids, daemon=True)
        thread.start()
        st.session_state["monitor_started"] = True
        st.sidebar.info("🛰️ IDS monitor started in background.")

    # ── LOAD ALERTS FROM CSV ─────────────────────────────────────────────
    LOG_FILE    = "logs/threat_alerts.csv"
    DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

    @st.cache_data(ttl=600)  # You can keep a short TTL so periodic reloads still fetch fresh data
    def load_data(path: str):
        if not os.path.exists(path):
            return pd.DataFrame(columns=["timestamp", "label", "src", "dst"])
        df = pd.read_csv(path, names=["timestamp", "label", "src", "dst"], header=0)
        df["timestamp"] = pd.to_datetime(
            df["timestamp"], format=DATE_FORMAT, utc=True, errors="coerce"
        )
        return df.dropna(subset=["timestamp"])

    df_alerts = load_data(LOG_FILE)
    if df_alerts.empty:
        st.warning("No IDS alerts have been logged yet.")
        return

    # ── The rest of your filter UI, charts, and table rendering ────────
    st.sidebar.header("Filters")
    min_ts = df_alerts["timestamp"].min().floor("H")
    max_ts = df_alerts["timestamp"].max().ceil("H")
    date_range = st.sidebar.date_input(
        "Alert Date Range",
        [min_ts.date(), max_ts.date()],
        min_value=min_ts.date(),
        max_value=max_ts.date(),
    )
    start_date = datetime.combine(date_range[0], datetime.min.time()).replace(tzinfo=pd.Timestamp.utcnow().tz)
    end_date   = datetime.combine(date_range[1], datetime.max.time()).replace(tzinfo=pd.Timestamp.utcnow().tz)

    attack_types = df_alerts["label"].unique().tolist()
    selected_attacks = st.sidebar.multiselect(
        "Attack Type", options=sorted(attack_types), default=sorted(attack_types)
    )
    src_filter = st.sidebar.text_input("Source IP Contains")
    dst_filter = st.sidebar.text_input("Destination IP Contains")

    mask = (
        (df_alerts["timestamp"] >= pd.to_datetime(start_date)) &
        (df_alerts["timestamp"] <= pd.to_datetime(end_date)) &
        (df_alerts["label"].isin(selected_attacks))
    )
    if src_filter:
        mask &= df_alerts["src"].str.contains(src_filter, na=False)
    if dst_filter:
        mask &= df_alerts["dst"].str.contains(dst_filter, na=False)

    df_filtered = df_alerts.loc[mask].copy()
    df_filtered.sort_values(by="timestamp", ascending=False, inplace=True)

    # ── Display key metrics, chart, and table (unchanged) ────────────
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric(
            "Total Alerts",
            f"{len(df_filtered):,}",
            delta=f"{len(df_alerts) - len(df_filtered):,}"
        )
    with col2:
        st.metric("Unique Source IPs", f"{df_filtered['src'].nunique():,}")
    with col3:
        st.metric("Unique Dest. IPs", f"{df_filtered['dst'].nunique():,}")
    days_span = (df_filtered["timestamp"].max() - df_filtered["timestamp"].min()).days + 1
    with col4:
        st.metric("Days Covered", f"{days_span}")

    st.markdown("---")
    st.subheader("Alerts Over Time")
    df_ts = df_filtered.set_index("timestamp")
    span_hours = (df_ts.index.max() - df_ts.index.min()) / pd.Timedelta(hours=1)
    freq, xlabel = ("H", "Hour") if span_hours <= 48 else ("D", "Day")
    ts_counts = (
        df_ts["label"]
        .resample(freq)
        .count()
        .rename("count")
        .reset_index()
    )

    chart = (
        alt.Chart(ts_counts)
           .mark_line(point=True)
           .encode(
               x=alt.X("timestamp:T", title=xlabel),
               y=alt.Y("count:Q", title="Number of Alerts"),
               tooltip=[alt.Tooltip("timestamp:T", title="Time"), alt.Tooltip("count:Q", title="Alerts")],
           )
           .properties(width=800, height=300)
    )
    st.altair_chart(chart, use_container_width=True)

    st.subheader("Recent Alerts")
    st.dataframe(
        df_filtered[["timestamp", "label", "src", "dst"]].head(20),
        use_container_width=True,
        height=300
    )

    if not df_filtered.empty:
        csv_bytes = df_filtered.to_csv(index=False).encode("utf-8")
        st.download_button(
            "Download Filtered Alerts as CSV",
            data=csv_bytes,
            file_name="filtered_threat_alerts.csv",
            mime="text/csv"
        )

# ── 9) MAIN LOGIC: SHOW LOGIN OR DASHBOARD BASED ON SESSION COOKIE/STATE ───────
if not st.session_state["logged_in"]:
    show_login_form()
else:
    show_dashboard()
