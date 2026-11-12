import os
import requests
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")

# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="AI Scam & Phishing Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown(
    """
    <style>

    /* Main background */
    .stApp {
        background-color: #f7f9fc;
    }

    /* Remove unnecessary top spacing */
    .block-container {
        padding-top: 2rem;
        padding-bottom: 3rem;
        max-width: 1200px;
    }

    /* Sidebar */
    section[data-testid="stSidebar"] {
        background-color: #111827;
    }

    section[data-testid="stSidebar"] * {
        color: white !important;
    }

    /* Main title */
    .main-title {
        font-size: 38px;
        font-weight: 800;
        color: #111827;
        margin-bottom: 5px;
    }

    .subtitle {
        font-size: 17px;
        color: #6b7280;
        margin-bottom: 25px;
    }

    /* Header card */
    .hero {
        background: linear-gradient(135deg, #111827, #1f2937);
        padding: 30px;
        border-radius: 18px;
        margin-bottom: 25px;
        color: white;
    }

    .hero h1 {
        color: white;
        margin: 0;
        font-size: 32px;
    }

    .hero p {
        color: #d1d5db;
        font-size: 16px;
        margin-top: 8px;
    }

    /* Info cards */
    .info-card {
        background: white;
        padding: 20px;
        border-radius: 14px;
        border: 1px solid #e5e7eb;
        margin-bottom: 15px;
    }

    .info-card h3 {
        margin-top: 0;
        color: #111827;
    }

    .info-card p {
        color: #6b7280;
    }

    /* API badges */
    .api-badge {
        display: inline-block;
        padding: 6px 12px;
        border-radius: 20px;
        background: #eef2ff;
        color: #3730a3;
        font-size: 13px;
        font-weight: 600;
        margin-right: 6px;
    }

    .ai-badge {
        display: inline-block;
        padding: 6px 12px;
        border-radius: 20px;
        background: #ecfdf5;
        color: #047857;
        font-size: 13px;
        font-weight: 600;
        margin-right: 6px;
    }

    /* Result box */
    .result-box {
        background: white;
        border: 1px solid #e5e7eb;
        border-radius: 16px;
        padding: 25px;
        margin-top: 20px;
    }

    /* Footer */
    .footer {
        text-align: center;
        color: #9ca3af;
        font-size: 13px;
        margin-top: 50px;
        padding: 20px;
    }

    /* Buttons */
    .stButton > button {
        border-radius: 10px;
        font-weight: 600;
    }

    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# BACKEND HELPER
# ============================================================

def call_backend(method: str, path: str, payload: dict = None, timeout: int = 30):

    url = f"{BACKEND_URL}{path}"

    try:

        if method == "GET":
            response = requests.get(
                url,
                params=payload,
                timeout=timeout
            )
        else:
            response = requests.post(
                url,
                json=payload,
                timeout=timeout
            )

        response.raise_for_status()

        return response.json(), None

    except requests.exceptions.ConnectionError:

        return None, (
            f"Backend is not reachable at {BACKEND_URL}. "
            "Please make sure FastAPI is running."
        )

    except requests.exceptions.Timeout:

        return None, "The backend took too long to respond."

    except requests.exceptions.HTTPError as error:

        return None, f"Backend returned an error: {error}"

    except Exception as error:

        return None, f"Unexpected error: {error}"


# ============================================================
# STATUS
# ============================================================

def status_badge(status: str):

    if status == "Safe":
        return "🟢 **SAFE**"

    elif status == "Suspicious":
        return "🟡 **SUSPICIOUS**"

    elif status == "Malicious":
        return "🔴 **MALICIOUS**"

    return "⚪ **UNKNOWN**"


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.markdown(
    """
    <div style="text-align:center; padding:15px 5px;">
        <div style="font-size:42px;">🛡️</div>
        <h2 style="margin:0;">AI Security</h2>
        <p style="color:#9ca3af;">Scam & Phishing Detection</p>
    </div>
    """,
    unsafe_allow_html=True,
)

st.sidebar.divider()

page = st.sidebar.radio(
    "APPLICATION",
    [
        "🏠 Home",
        "🔗 URL Scanner",
        "📧 Email Scanner",
        "💬 SMS Scanner",
        "🤖 AI Assistant",
        "📊 Dashboard",
    ],
)

st.sidebar.divider()

health, health_error = call_backend("GET", "/health")

if health:
    st.sidebar.success("● Backend Online")
else:
    st.sidebar.error("● Backend Offline")


st.sidebar.markdown(
    """
    <div style="margin-top:20px; font-size:12px; color:#9ca3af;">
        <b>Technology Stack</b><br><br>
        FastAPI<br>
        Streamlit<br>
        Groq AI API<br>
        VirusTotal API<br>
        SQLite Database
    </div>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# HOME
# ============================================================

if page == "🏠 Home":

    st.markdown(
        """
        <div class="hero">
            <h1>🛡️ AI Scam & Phishing Detection System</h1>
            <p>
                An AI-assisted cybersecurity system for detecting
                suspicious URLs, emails and SMS messages.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        '<span class="ai-badge">🤖 AI Powered</span>'
        '<span class="api-badge">🔌 API Integrated</span>'
        '<span class="api-badge">🛡️ Threat Intelligence</span>',
        unsafe_allow_html=True,
    )

    st.write("")

    st.markdown("## What can this system detect?")

    col1, col2, col3 = st.columns(3)

    with col1:

        st.markdown(
            """
            <div class="info-card">
                <h3>🔗 Suspicious URLs</h3>
                <p>
                Analyze URLs and identify potentially dangerous
                or malicious links using threat intelligence.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col2:

        st.markdown(
            """
            <div class="info-card">
                <h3>📧 Email Scams</h3>
                <p>
                Analyze email content and identify common
                phishing and social-engineering signals.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col3:

        st.markdown(
            """
            <div class="info-card">
                <h3>💬 SMS Scams</h3>
                <p>
                Detect suspicious messages containing scam,
                urgency, payment or credential-related signals.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("## How the system works")

    st.markdown(
        """
        <div class="info-card">

        **1️⃣ User Input**

        URL, email or SMS is submitted to the application.

        ↓

        **2️⃣ FastAPI Backend**

        The frontend sends the request to the FastAPI API layer.

        ↓

        **3️⃣ AI & Security APIs**

        The system can use **Groq AI** for intelligent analysis
        and **VirusTotal** for URL threat intelligence.

        ↓

        **4️⃣ Risk Analysis**

        The system calculates a risk score and classification.

        ↓

        **5️⃣ Result**

        The user receives a Safe, Suspicious or Malicious result.

        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("## Technologies used")

    c1, c2, c3, c4, c5 = st.columns(5)

    c1.metric("Frontend", "Streamlit")
    c2.metric("Backend", "FastAPI")
    c3.metric("AI", "Groq API")
    c4.metric("Security", "VirusTotal")
    c5.metric("Database", "SQLite")


# ============================================================
# URL SCANNER
# ============================================================

elif page == "🔗 URL Scanner":

    st.markdown(
        '<div class="main-title">🔗 URL Scanner</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        '<div class="subtitle">'
        'Analyze a suspicious website URL using threat intelligence.'
        '</div>',
        unsafe_allow_html=True,
    )

    url_input = st.text_input(
        "Website URL",
        placeholder="https://example.com",
    )

    if st.button("🔍 Analyze URL", type="primary", use_container_width=True):

        if not url_input.strip():

            st.warning("Please enter a URL.")

        else:

            with st.spinner("Analyzing URL..."):

                result, error = call_backend(
                    "POST",
                    "/api/url/scan",
                    {"url": url_input.strip()},
                )

            if error:

                st.error(error)

            else:

                st.markdown(
                    '<div class="result-box">',
                    unsafe_allow_html=True,
                )

                col1, col2 = st.columns(2)

                with col1:

                    st.metric(
                        "Risk Score",
                        f"{result['risk_score']}/100",
                    )

                with col2:

                    st.markdown("### Status")
                    st.markdown(status_badge(result["status"]))

                st.markdown("### Analysis")

                st.write(result["explanation"])

                with st.expander("Technical Details"):

                    st.json(result["details"])

                st.markdown("</div>", unsafe_allow_html=True)


# ============================================================
# EMAIL SCANNER
# ============================================================

elif page == "📧 Email Scanner":

    st.markdown(
        '<div class="main-title">📧 Email Scam Scanner</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        '<div class="subtitle">'
        'Analyze suspicious email content for phishing and scam signals.'
        '</div>',
        unsafe_allow_html=True,
    )

    email_input = st.text_area(
        "Email content",
        height=220,
        placeholder=(
            "Paste the complete suspicious email here..."
        ),
    )

    if st.button(
        "🔍 Analyze Email",
        type="primary",
        use_container_width=True,
    ):

        if not email_input.strip():

            st.warning("Please paste the email content.")

        else:

            with st.spinner("AI is analyzing the email..."):

                result, error = call_backend(
                    "POST",
                    "/api/email/scan",
                    {"email_text": email_input.strip()},
                )

            if error:

                st.error(error)

            else:

                st.markdown(
                    '<div class="result-box">',
                    unsafe_allow_html=True,
                )

                col1, col2 = st.columns(2)

                with col1:

                    st.metric(
                        "Risk Score",
                        f"{result['risk_score']}/100",
                    )

                with col2:

                    st.markdown("### Status")
                    st.markdown(status_badge(result["status"]))

                st.markdown("### AI Analysis")

                st.write(result["explanation"])

                if result.get("matched_keywords"):

                    st.markdown("### Detected Signals")

                    st.write(
                        ", ".join(result["matched_keywords"])
                    )

                st.markdown("</div>", unsafe_allow_html=True)


# ============================================================
# SMS SCANNER
# ============================================================

elif page == "💬 SMS Scanner":

    st.markdown(
        '<div class="main-title">💬 SMS Scam Scanner</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        '<div class="subtitle">'
        'Check suspicious SMS messages for scam indicators.'
        '</div>',
        unsafe_allow_html=True,
    )

    sms_input = st.text_area(
        "SMS content",
        height=160,
        placeholder="Paste suspicious SMS here...",
    )

    if st.button(
        "🔍 Analyze SMS",
        type="primary",
        use_container_width=True,
    ):

        if not sms_input.strip():

            st.warning("Please enter the SMS content.")

        else:

            with st.spinner("Analyzing message..."):

                result, error = call_backend(
                    "POST",
                    "/api/sms/scan",
                    {"sms_text": sms_input.strip()},
                )

            if error:

                st.error(error)

            else:

                st.markdown(
                    '<div class="result-box">',
                    unsafe_allow_html=True,
                )

                col1, col2 = st.columns(2)

                with col1:

                    st.metric(
                        "Risk Score",
                        f"{result['risk_score']}/100",
                    )

                with col2:

                    st.markdown("### Status")
                    st.markdown(status_badge(result["status"]))

                st.markdown("### Analysis")

                st.write(result["explanation"])

                if result.get("matched_keywords"):

                    st.markdown("### Detected Signals")

                    st.write(
                        ", ".join(result["matched_keywords"])
                    )

                st.markdown("</div>", unsafe_allow_html=True)


# ============================================================
# AI ASSISTANT
# ============================================================

elif page == "🤖 AI Assistant":

    st.markdown(
        '<div class="main-title">🤖 AI Cybersecurity Assistant</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        '<div class="subtitle">'
        'Ask questions about phishing, scams, passwords and online safety.'
        '</div>',
        unsafe_allow_html=True,
    )

    if "chat_history" not in st.session_state:

        st.session_state.chat_history = []

    for question, answer in st.session_state.chat_history:

        with st.chat_message("user"):

            st.write(question)

        with st.chat_message("assistant"):

            st.write(answer)

    question = st.chat_input(
        "Ask a cybersecurity question..."
    )

    if question:

        with st.chat_message("user"):

            st.write(question)

        with st.chat_message("assistant"):

            with st.spinner("AI is thinking..."):

                result, error = call_backend(
                    "POST",
                    "/api/chatbot/ask",
                    {"question": question},
                )

            if error:

                st.error(error)

            else:

                st.write(result["answer"])

                st.session_state.chat_history.append(
                    (question, result["answer"])
                )


# ============================================================
# DASHBOARD
# ============================================================

elif page == "📊 Dashboard":

    st.markdown(
        '<div class="main-title">📊 Security Dashboard</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        '<div class="subtitle">'
        'Overview of scans performed by the detection system.'
        '</div>',
        unsafe_allow_html=True,
    )

    stats, error = call_backend(
        "GET",
        "/api/dashboard/stats",
    )

    if error:

        st.error(error)

    else:

        col1, col2, col3 = st.columns(3)

        col1.metric(
            "🔗 URLs Scanned",
            stats["total_urls_scanned"],
        )

        col2.metric(
            "📧 Emails Scanned",
            stats["total_emails_scanned"],
        )

        col3.metric(
            "💬 SMS Scanned",
            stats["total_sms_scanned"],
        )

        st.divider()

        st.subheader("Detection Breakdown")

        breakdown = stats["breakdown_by_status"]

        if breakdown:

            st.bar_chart(breakdown)

        else:

            st.info(
                "No scans have been performed yet."
            )

    st.divider()

    st.subheader("Recent Scan History")

    history, hist_error = call_backend(
        "GET",
        "/api/dashboard/history",
        {"limit": 10},
    )

    if hist_error:

        st.error(hist_error)

    elif history:

        tab1, tab2, tab3 = st.tabs(
            [
                "🔗 URLs",
                "📧 Emails",
                "💬 SMS",
            ]
        )

        with tab1:

            if history.get("urls"):

                for scan in history["urls"]:

                    st.write(
                        f"{status_badge(scan['status'])} — "
                        f"{scan['url']} "
                        f"(Score: {scan['risk_score']})"
                    )

            else:

                st.info("No URL scans yet.")

        with tab2:

            if history.get("emails"):

                for scan in history["emails"]:

                    preview = (
                        scan["email_text"][:80]
                        + (
                            "..."
                            if len(scan["email_text"]) > 80
                            else ""
                        )
                    )

                    st.write(
                        f"{status_badge(scan['status'])} — "
                        f"{preview} "
                        f"(Score: {scan['risk_score']})"
                    )

            else:

                st.info("No email scans yet.")

        with tab3:

            if history.get("sms"):

                for scan in history["sms"]:

                    preview = (
                        scan["sms_text"][:80]
                        + (
                            "..."
                            if len(scan["sms_text"]) > 80
                            else ""
                        )
                    )

                    st.write(
                        f"{status_badge(scan['status'])} — "
                        f"{preview} "
                        f"(Score: {scan['risk_score']})"
                    )

            else:

                st.info("No SMS scans yet.")


# ============================================================
# FOOTER
# ============================================================

st.markdown(
    """
    <div class="footer">
        AI Scam & Phishing Detection System
        <br>
        MSc Artificial Intelligence Project
        <br><br>
        FastAPI • Streamlit • Groq API • VirusTotal API • SQLite
    </div>
    """,
    unsafe_allow_html=True,
)