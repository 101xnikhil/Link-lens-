import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, Text, DateTime, Index
from app.database.session import Base

class ScanRecord(Base):
    __tablename__ = "scans"

    scan_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    submitted_url = Column(Text, nullable=False)
    normalized_url = Column(Text, nullable=False, index=True)
    hostname = Column(String(255), nullable=False, index=True)
    domain = Column(String(255), nullable=True)
    risk_score = Column(Integer, nullable=False)
    risk_level = Column(String(32), nullable=False, index=True) # low, moderate, high, critical
    analysis_summary = Column(Text, nullable=False)
    indicators_json = Column(Text, nullable=False)
    url_details_json = Column(Text, nullable=False)
    recommendations_json = Column(Text, nullable=False)
    threat_intelligence_status = Column(String(64), nullable=False, default="not_configured")
    threat_intel_json = Column(Text, nullable=False)
    analyzed_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    __table_args__ = (
        Index("idx_scans_analyzed_at", "analyzed_at"),
        Index("idx_scans_risk_level", "risk_level"),
    )
