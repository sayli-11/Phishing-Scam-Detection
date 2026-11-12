import os
import re
import json
import base64
import requests

from fastapi import FastAPI, Depends
from pydantic import BaseModel
from dotenv import load_dotenv
from sqlalchemy.orm import Session

from database import (
    init_db,
    get_db,
    save_url_scan,
    save_email_scan,
    save_sms_scan,
    save_chat_log,
    get_dashboard_stats,
    get_scan_history,
)

load_dotenv()

# ============================================================
# CONFIGURATION
# ============================================================

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

app = FastAPI(
    title="AI Phishing & Scam Detection API",
    description="AI-assisted phishing, scam and malicious URL detection system",
    version="1.0"
)


@app.on_event("startup")
def startup():
    init_db()


# ============================================================
# REQUEST MODELS
# ============================================================

class URLScanRequest(BaseModel):
    url: str


class EmailScanRequest(BaseModel):
    email_text: str


class SMSScanRequest(BaseModel):
    sms_text: str


class ChatRequest(BaseModel):
    question: str


# ============================================================
# KEYWORD DATABASE
# ============================================================

URGENT_KEYWORDS = [
    "urgent",
    "immediately",
    "act now",
    "expires today",
    "final notice",
    "action required",
    "within 24 hours",
    "last warning",
]

CREDENTIAL_KEYWORDS = [
    "verify your password",
    "confirm your account",
    "login to continue",
    "update your billing",
    "verify your account",
    "confirm your identity",
    "enter your password",
    "login",
    "sign in",
]

BANKING_KEYWORDS = [
    "account suspended",
    "unusual activity",
    "verify your bank",
    "wire transfer",
    "otp code",
    "bank account",
    "credit card",
    "debit card",
    "transaction",
    "payment failed",
]

PRIZE_KEYWORDS = [
    "you have won",
    "claim your prize",
    "lottery",
    "free gift",
    "congratulations",
    "winner",
    "cash prize",
    "reward",
]

SUSPICIOUS_URL_WORDS = [
    "login",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "update",
    "bank",
    "wallet",
    "payment",
    "signin",
    "password",
    "confirm",
    "free",
    "prize",
    "reward",
    "claim",
]


# ============================================================
# BASIC RULE-BASED TEXT SCORING
# ============================================================

def score_text_rules(text: str):
    """
    Rule-based phishing/scam detection.
    Returns score and matched signals.
    """

    text_lower = text.lower()

    score = 0
    matched = []

    for keyword in URGENT_KEYWORDS:
        if keyword in text_lower:
            score += 10
            matched.append(keyword)

    for keyword in CREDENTIAL_KEYWORDS:
        if keyword in text_lower:
            score += 20
            matched.append(keyword)

    for keyword in BANKING_KEYWORDS:
        if keyword in text_lower:
            score += 20
            matched.append(keyword)

    for keyword in PRIZE_KEYWORDS:
        if keyword in text_lower:
            score += 15
            matched.append(keyword)

    return min(score, 100), matched


# ============================================================
# GROQ AI
# ============================================================

def get_llm():
    from langchain_groq import ChatGroq

    return ChatGroq(
        model="openai/gpt-oss-20b",
        groq_api_key=GROQ_API_KEY,
        temperature=0
    )


def ai_analyze_text(text: str, content_type: str, rule_score: int, matched: list):
    """
    Uses Groq AI to analyze emails and SMS messages.
    Returns:
        risk_score
        status
        explanation
    """

    if not GROQ_API_KEY:
        return {
            "risk_score": rule_score,
            "status": status_from_score(rule_score),
            "explanation": (
                f"Rule-based analysis detected these signals: "
                f"{', '.join(matched) if matched else 'none'}."
            )
        }

    try:
        llm = get_llm()

        prompt = f"""
You are an AI cybersecurity detection system.

Analyze the following {content_type} for phishing, fraud, scam,
social engineering, credential theft, financial fraud, or malicious intent.

CONTENT:
{text}

Rule-based preliminary score: {rule_score}/100
Detected signals: {matched}

Return ONLY valid JSON in exactly this format:

{{
  "risk_score": 0,
  "status": "Safe",
  "explanation": "Short explanation in English."
}}

Rules:

1. risk_score must be an integer from 0 to 100.
2. Status must be exactly one of:
   Safe
   Suspicious
   Malicious

3. Use:
   0-24 = Safe
   25-59 = Suspicious
   60-100 = Malicious

4. Look for:
   - urgency
   - requests for passwords or OTPs
   - fake account verification
   - banking/payment requests
   - suspicious links
   - prizes or rewards
   - impersonation
   - threats
   - social engineering
   - requests for sensitive information

5. The explanation MUST be in English.
6. Do not use Hindi, Marathi, Nepali or any other language.
7. Do not add Markdown.
8. Return JSON only.
"""

        response = llm.invoke(prompt)

        content = response.content.strip()

        # Remove accidental markdown fences
        content = content.replace("```json", "").replace("```", "").strip()

        result = json.loads(content)

        risk_score = int(result.get("risk_score", rule_score))
        risk_score = max(0, min(100, risk_score))

        status = result.get("status", status_from_score(risk_score))

        if status not in ["Safe", "Suspicious", "Malicious"]:
            status = status_from_score(risk_score)

        explanation = result.get(
            "explanation",
            "AI analysis completed successfully."
        )

        return {
            "risk_score": risk_score,
            "status": status,
            "explanation": explanation
        }

    except Exception as e:

        # AI failure should NOT make a suspicious message appear safe.
        fallback_score = rule_score

        return {
            "risk_score": fallback_score,
            "status": status_from_score(fallback_score),
            "explanation": (
                f"Automated analysis detected the following signals: "
                f"{', '.join(matched) if matched else 'no strong keyword signals'}. "
                f"AI analysis was unavailable, so the system used rule-based detection."
            )
        }


# ============================================================
# VIRUSTOTAL
# ============================================================

def check_virustotal(url: str):

    if not VIRUSTOTAL_API_KEY:
        return {
            "available": False,
            "malicious": 0,
            "suspicious": 0,
            "message": "VirusTotal API key is not configured."
        }

    try:

        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY
        }

        url_id = base64.urlsafe_b64encode(
            url.encode()
        ).decode().strip("=")

        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=15
        )

        if response.status_code == 200:

            data = response.json()

            stats = (
                data
                .get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )

            return {
                "available": True,
                "found": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0)
            }

        elif response.status_code == 404:

            return {
                "available": True,
                "found": False,
                "malicious": 0,
                "suspicious": 0,
                "message": "URL not found in the existing VirusTotal database."
            }

        else:

            return {
                "available": True,
                "found": False,
                "malicious": 0,
                "suspicious": 0,
                "message": f"VirusTotal returned HTTP {response.status_code}."
            }

    except Exception as e:

        return {
            "available": False,
            "found": False,
            "malicious": 0,
            "suspicious": 0,
            "message": str(e)
        }


# ============================================================
# URL HEURISTIC ANALYSIS
# ============================================================

def analyze_url_patterns(url: str):

    score = 0
    signals = []

    url_lower = url.lower()

    # HTTP instead of HTTPS
    if url_lower.startswith("http://"):
        score += 10
        signals.append("uses HTTP instead of HTTPS")

    # Suspicious words
    for word in SUSPICIOUS_URL_WORDS:

        if word in url_lower:

            score += 8
            signals.append(f"contains suspicious term '{word}'")

    # IP address instead of domain
    ip_pattern = r"https?://(?:\d{1,3}\.){3}\d{1,3}"

    if re.search(ip_pattern, url):
        score += 30
        signals.append("uses an IP address instead of a normal domain")

    # @ symbol
    if "@" in url:
        score += 25
        signals.append("contains @ symbol")

    # Punycode
    if "xn--" in url_lower:
        score += 30
        signals.append("contains punycode")

    # Excessive subdomains
    try:

        domain = url_lower.split("://", 1)[-1].split("/", 1)[0]
        domain_without_port = domain.split(":", 1)[0]

        dot_count = domain_without_port.count(".")

        if dot_count >= 4:
            score += 20
            signals.append("contains an unusually large number of subdomains")

    except Exception:
        pass

    # Long URL
    if len(url) > 100:
        score += 10
        signals.append("unusually long URL")

    # URL shorteners
    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "cutt.ly"
    ]

    for shortener in shorteners:

        if shortener in url_lower:
            score += 20
            signals.append(f"uses URL shortener {shortener}")

    return min(score, 100), signals


# ============================================================
# URL FINAL SCORE
# ============================================================

def calculate_url_score(vt_result, heuristic_score):

    vt_score = 0

    if vt_result.get("malicious", 0) > 0:
        vt_score += min(
            vt_result.get("malicious", 0) * 20,
            80
        )

    if vt_result.get("suspicious", 0) > 0:
        vt_score += min(
            vt_result.get("suspicious", 0) * 10,
            40
        )

    vt_score = min(vt_score, 100)

    # If VirusTotal has a known malicious result,
    # give it strong weight.
    if vt_score >= 60:
        return vt_score

    # Combine heuristic + VirusTotal information.
    final_score = max(
        heuristic_score,
        vt_score
    )

    return min(final_score, 100)


# ============================================================
# STATUS
# ============================================================

def status_from_score(score: int):

    if score >= 60:
        return "Malicious"

    if score >= 25:
        return "Suspicious"

    return "Safe"


# ============================================================
# URL EXPLANATION
# ============================================================

def generate_url_explanation(
    url,
    score,
    status,
    signals,
    vt_result
):

    if status == "Safe":

        base = (
            "The URL does not show strong phishing indicators "
            "based on the available automated checks."
        )

    elif status == "Suspicious":

        base = (
            "The URL contains characteristics that may be associated "
            "with phishing or deceptive websites."
        )

    else:

        base = (
            "The URL shows strong indicators associated with "
            "malicious or phishing activity."
        )

    if signals:

        base += " Detected signals: " + ", ".join(signals) + "."

    if vt_result.get("malicious", 0) > 0:

        base += (
            f" VirusTotal detected {vt_result.get('malicious')} "
            "malicious security-engine results."
        )

    elif vt_result.get("suspicious", 0) > 0:

        base += (
            f" VirusTotal reported "
            f"{vt_result.get('suspicious')} suspicious detections."
        )

    elif vt_result.get("found") is False:

        base += (
            " The URL was not found in the existing VirusTotal database, "
            "so the system also used URL-pattern analysis."
        )

    return base


# ============================================================
# URL SCANNER
# ============================================================

@app.post("/api/url/scan")
def scan_url(
    request: URLScanRequest,
    db: Session = Depends(get_db)
):

    url = request.url.strip()

    # VirusTotal
    vt_result = check_virustotal(url)

    # Local URL analysis
    heuristic_score, signals = analyze_url_patterns(url)

    # Final score
    risk_score = calculate_url_score(
        vt_result,
        heuristic_score
    )

    status = status_from_score(risk_score)

    explanation = generate_url_explanation(
        url,
        risk_score,
        status,
        signals,
        vt_result
    )

    record = save_url_scan(
        db,
        url,
        risk_score,
        status,
        explanation
    )

    return {
        "id": record.id,
        "url": url,
        "risk_score": risk_score,
        "status": status,
        "explanation": explanation,
        "details": {
            "virustotal": vt_result,
            "url_heuristics": {
                "score": heuristic_score,
                "signals": signals
            }
        }
    }


# ============================================================
# EMAIL SCANNER
# ============================================================

@app.post("/api/email/scan")
def scan_email(
    request: EmailScanRequest,
    db: Session = Depends(get_db)
):

    text = request.email_text.strip()

    rule_score, matched = score_text_rules(text)

    ai_result = ai_analyze_text(
        text,
        "email message",
        rule_score,
        matched
    )

    record = save_email_scan(
        db,
        text,
        ai_result["risk_score"],
        ai_result["status"],
        matched,
        ai_result["explanation"]
    )

    return {
        "id": record.id,
        "risk_score": ai_result["risk_score"],
        "status": ai_result["status"],
        "matched_keywords": matched,
        "explanation": ai_result["explanation"]
    }


# ============================================================
# SMS SCANNER
# ============================================================

@app.post("/api/sms/scan")
def scan_sms(
    request: SMSScanRequest,
    db: Session = Depends(get_db)
):

    text = request.sms_text.strip()

    rule_score, matched = score_text_rules(text)

    ai_result = ai_analyze_text(
        text,
        "SMS message",
        rule_score,
        matched
    )

    record = save_sms_scan(
        db,
        text,
        ai_result["risk_score"],
        ai_result["status"],
        matched,
        ai_result["explanation"]
    )

    return {
        "id": record.id,
        "risk_score": ai_result["risk_score"],
        "status": ai_result["status"],
        "matched_keywords": matched,
        "explanation": ai_result["explanation"]
    }


# ============================================================
# AI CHATBOT
# ============================================================

@app.post("/api/chatbot/ask")
def ask_chatbot(
    request: ChatRequest,
    db: Session = Depends(get_db)
):

    if not GROQ_API_KEY:

        answer = (
            "The AI assistant is not configured yet. "
            "Please add the GROQ_API_KEY to the backend .env file."
        )

    else:

        try:

            llm = get_llm()

            prompt = f"""
You are a cybersecurity awareness assistant.

Answer the user's question about:
- phishing
- online scams
- suspicious messages
- password security
- online safety
- cyber hygiene
- malicious websites

Give a simple, clear answer in English.

User question:
{request.question}
"""

            response = llm.invoke(prompt)

            answer = response.content

        except Exception as e:

            answer = (
                "The AI assistant could not process the request right now."
            )

    save_chat_log(
        db,
        request.question,
        answer
    )

    return {
        "question": request.question,
        "answer": answer
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():

    return {
        "status": "ok",
        "virustotal_configured": bool(VIRUSTOTAL_API_KEY),
        "groq_configured": bool(GROQ_API_KEY)
    }


# ============================================================
# DASHBOARD
# ============================================================

@app.get("/api/dashboard/stats")
def dashboard_stats(
    db: Session = Depends(get_db)
):

    return get_dashboard_stats(db)


@app.get("/api/dashboard/history")
def dashboard_history(
    limit: int = 20,
    db: Session = Depends(get_db)
):

    return get_scan_history(
        db,
        limit
    )