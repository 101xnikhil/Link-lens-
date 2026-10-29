from typing import List, Dict, Any, Tuple

def calculate_risk_score(
    indicators: List[Dict[str, Any]],
    threat_intel: Dict[str, Any]
) -> Tuple[int, str, str]:
    """
    Computes transparent composite risk score (0-100), risk level, and explanatory summary.
    
    Risk Level Definitions:
    - 0-24: Low observed risk
    - 25-49: Moderate observed risk
    - 50-74: High observed risk
    - 75-100: Critical observed risk
    """
    detected_indicators = [ind for ind in indicators if ind.get("status") == "detected"]

    # If verified threat intelligence matched a known threat
    if threat_intel.get("status") == "threat_detected":
        matches = threat_intel.get("matches", [])
        threat_str = ", ".join(matches) if matches else "Verified Malicious Threat"
        score = 95
        risk_level = "critical"
        summary = (
            f"CRITICAL THREAT: Verified malicious entity detected by threat intelligence "
            f"({threat_str}). Multiple indicators corroborate severe danger. Access strongly discouraged."
        )
        return score, risk_level, summary

    # Aggregate heuristic weights with non-linear saturation to avoid runaway stacking
    raw_score = sum(ind.get("weight", 0) for ind in detected_indicators)

    # Scale and cap score
    # Formula: using an asymptotic or bounded mapping to ensure a balanced 0-100 spread
    if raw_score == 0:
        score = 5 # Heuristic baseline: Never 0, because absence of evidence is not evidence of absence
    elif raw_score <= 18:
        # Weak single indicator (e.g. HTTP only, or mild length)
        score = min(22, 5 + raw_score)
    elif raw_score <= 45:
        score = 25 + int((raw_score - 18) * 0.8)
    elif raw_score <= 75:
        score = 50 + int((raw_score - 45) * 0.75)
    else:
        score = 75 + int(min(24, (raw_score - 75) * 0.5))

    # Strict bounds clamp
    score = max(0, min(100, score))

    # Map to risk level
    if score >= 75:
        risk_level = "critical"
    elif score >= 50:
        risk_level = "high"
    elif score >= 25:
        risk_level = "moderate"
    else:
        risk_level = "low"

    # Construct explanatory dynamic summary
    critical_detected = [i["name"] for i in detected_indicators if i.get("severity") in ("critical", "high")]
    medium_detected = [i["name"] for i in detected_indicators if i.get("severity") == "medium"]

    if risk_level == "critical":
        summary = (
            f"Critical risk profile ({score}/100): Identified dangerous signals including {', '.join(critical_detected[:3])}. "
            f"Strong indicators of phishing, deceptive brand impersonation, or malicious delivery."
        )
    elif risk_level == "high":
        summary = (
            f"High risk profile ({score}/100): Suspicious patterns detected including {', '.join(critical_detected[:2] or medium_detected[:2])}. "
            f"Significant deceptive characteristics suggest caution is warranted."
        )
    elif risk_level == "moderate":
        summary = (
            f"Moderate risk profile ({score}/100): URL exhibits anomalous characteristics such as {', '.join(medium_detected[:2] or [i['name'] for i in detected_indicators[:2]])}. "
            f"Heuristic findings warrant user diligence."
        )
    else:
        if detected_indicators:
            summary = (
                f"Low observed risk ({score}/100): Minimal anomalies observed ({', '.join([i['name'] for i in detected_indicators[:2]])}). "
                f"No prominent malicious indicators found. Note that low risk does not guarantee complete safety."
            )
        else:
            summary = (
                f"Low observed risk ({score}/100): No known suspicious patterns detected in structural and heuristic checks. "
                f"Always verify destination credentials before submitting sensitive information."
            )

    return score, risk_level, summary
