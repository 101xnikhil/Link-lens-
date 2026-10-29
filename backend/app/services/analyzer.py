import uuid
from datetime import datetime
from typing import Dict, Any

from app.services.url_parser import normalize_and_parse_url
from app.services.heuristics import run_heuristics
from app.services.threat_intel import check_threat_intelligence
from app.services.scoring import calculate_risk_score
from app.services.recommendations import generate_recommendations

async def analyze_url(raw_url: str) -> Dict[str, Any]:
    """
    Coordinates the full URL security analysis lifecycle:
    1. Validation and safe normalization (no external requests to target URL)
    2. Deep structural and heuristic indicators evaluation
    3. Threat intelligence verification (Google Safe Browsing with fallback)
    4. Deterministic, transparent risk scoring
    5. Actionable defensive recommendations generation
    """
    # 1. Parse and validate
    details = normalize_and_parse_url(raw_url)

    # 2. Run heuristic checks
    indicators = run_heuristics(details)

    # 3. Threat intelligence lookup (optional/configurable)
    threat_intel = await check_threat_intelligence(details["normalized_url"])

    # 4. Calculate risk score & risk level
    score, risk_level, summary = calculate_risk_score(indicators, threat_intel)

    # 5. Generate safety recommendations
    recommendations = generate_recommendations(risk_level, indicators, threat_intel)

    scan_id = str(uuid.uuid4())
    analyzed_at = datetime.utcnow().isoformat() + "Z"

    # Assemble cleaned url_details matching schema
    url_details_clean = {
        "submitted_url": details["submitted_url"],
        "normalized_url": details["normalized_url"],
        "scheme": details["scheme"],
        "hostname": details["hostname"],
        "domain": details["domain"],
        "subdomain": details["subdomain"],
        "tld": details["tld"],
        "path": details["path"],
        "query": details["query"],
        "port": details["port"],
        "url_length": details["url_length"],
        "hostname_length": details["hostname_length"],
        "has_ip": details["has_ip"],
        "subdomain_count": details["subdomain_count"],
        "is_punycode": details["is_punycode"],
        "is_shortened": details.get("is_shortened", False),
        "entropy": details["entropy"],
        "suspicious_keywords_found": details.get("suspicious_keywords_found", [])
    }

    return {
        "scan_id": scan_id,
        "submitted_url": details["submitted_url"],
        "normalized_url": details["normalized_url"],
        "hostname": details["hostname"],
        "domain": details["domain"],
        "risk_score": score,
        "risk_level": risk_level,
        "summary": summary,
        "indicators": indicators,
        "url_details": url_details_clean,
        "recommendations": recommendations,
        "threat_intelligence": threat_intel,
        "analyzed_at": analyzed_at
    }
