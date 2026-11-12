from datetime import datetime

from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.orm import sessionmaker, declarative_base


# SQLite database — no MySQL installation/password required
DATABASE_URL = "sqlite:///./phishing_detection.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()


class URLScan(Base):
    __tablename__ = "url_scans"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(2048), nullable=False)
    risk_score = Column(Integer, nullable=False)
    status = Column(String(20), nullable=False)
    explanation = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class EmailScan(Base):
    __tablename__ = "email_scans"

    id = Column(Integer, primary_key=True, index=True)
    email_text = Column(Text, nullable=False)
    risk_score = Column(Integer, nullable=False)
    status = Column(String(20), nullable=False)
    matched_keywords = Column(String(500), nullable=True)
    explanation = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class SMSScan(Base):
    __tablename__ = "sms_scans"

    id = Column(Integer, primary_key=True, index=True)
    sms_text = Column(Text, nullable=False)
    risk_score = Column(Integer, nullable=False)
    status = Column(String(20), nullable=False)
    matched_keywords = Column(String(500), nullable=True)
    explanation = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class ChatLog(Base):
    __tablename__ = "chat_logs"

    id = Column(Integer, primary_key=True, index=True)
    question = Column(Text, nullable=False)
    answer = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def save_url_scan(db, url, risk_score, status, explanation=None):
    record = URLScan(
        url=url,
        risk_score=risk_score,
        status=status,
        explanation=explanation
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def save_email_scan(
    db,
    email_text,
    risk_score,
    status,
    matched_keywords,
    explanation=None
):
    record = EmailScan(
        email_text=email_text,
        risk_score=risk_score,
        status=status,
        matched_keywords=", ".join(matched_keywords),
        explanation=explanation
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def save_sms_scan(
    db,
    sms_text,
    risk_score,
    status,
    matched_keywords,
    explanation=None
):
    record = SMSScan(
        sms_text=sms_text,
        risk_score=risk_score,
        status=status,
        matched_keywords=", ".join(matched_keywords),
        explanation=explanation
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def save_chat_log(db, question, answer):
    record = ChatLog(
        question=question,
        answer=answer
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def get_scan_history(db, limit=20):
    urls = (
        db.query(URLScan)
        .order_by(URLScan.created_at.desc())
        .limit(limit)
        .all()
    )

    emails = (
        db.query(EmailScan)
        .order_by(EmailScan.created_at.desc())
        .limit(limit)
        .all()
    )

    smses = (
        db.query(SMSScan)
        .order_by(SMSScan.created_at.desc())
        .limit(limit)
        .all()
    )

    return {
        "urls": urls,
        "emails": emails,
        "sms": smses
    }


def get_dashboard_stats(db):
    total_urls = db.query(URLScan).count()
    total_emails = db.query(EmailScan).count()
    total_sms = db.query(SMSScan).count()

    threats_by_status = {}

    for model in (URLScan, EmailScan, SMSScan):
        for status, in db.query(model.status).all():
            threats_by_status[status] = (
                threats_by_status.get(status, 0) + 1
            )

    return {
        "total_urls_scanned": total_urls,
        "total_emails_scanned": total_emails,
        "total_sms_scanned": total_sms,
        "breakdown_by_status": threats_by_status
    }