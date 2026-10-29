from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field

class AnalyzeRequest(BaseModel):
    url: str = Field(..., description="The URL to be analyzed for security indicators", min_length=1, max_length=2048)

class IndicatorItem(BaseModel):
    id: str
    name: str
    category: str # structure, domain, pattern, reputation
    severity: str # info, low, medium, high, critical
    status: str # detected, clean, neutral, skipped
    explanation: str
    recommended_action: str
    weight: int

class UrlDetails(BaseModel):
    submitted_url: str
    normalized_url: str
    scheme: str
    hostname: str
    domain: str
    subdomain: str
    tld: str
    path: str
    query: str
    port: Optional[int] = None
    url_length: int
    hostname_length: int
    has_ip: bool
    subdomain_count: int
    is_punycode: bool
    is_shortened: bool
    entropy: float
    suspicious_keywords_found: List[str] = []

class ThreatIntelResult(BaseModel):
    checked: bool
    status: str # clean, threat_detected, not_configured, lookup_failed
    provider: str
    details: Optional[str] = None
    matches: List[str] = []

class ScanResponse(BaseModel):
    scan_id: str
    submitted_url: str
    normalized_url: str
    hostname: str
    domain: str
    risk_score: int
    risk_level: str # low, moderate, high, critical
    summary: str
    indicators: List[IndicatorItem]
    url_details: UrlDetails
    recommendations: List[str]
    threat_intelligence: ThreatIntelResult
    analyzed_at: str

class ScanHistoryItem(BaseModel):
    scan_id: str
    submitted_url: str
    normalized_url: str
    hostname: str
    domain: Optional[str] = None
    risk_score: int
    risk_level: str
    summary: str
    analyzed_at: str

class ScanHistoryResponse(BaseModel):
    items: List[ScanHistoryItem]
    total: int
    page: int
    limit: int

class StatsResponse(BaseModel):
    total_scans: int
    critical_risk: int
    high_risk: int
    medium_risk: int
    low_risk: int
    avg_risk_score: float
    risk_distribution: Dict[str, int]
    recent_scans: List[ScanHistoryItem]
