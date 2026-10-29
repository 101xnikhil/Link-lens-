import pytest
from app.services.url_parser import normalize_and_parse_url, is_ip_address, calculate_entropy
from app.services.heuristics import run_heuristics
from app.services.scoring import calculate_risk_score
from app.services.recommendations import generate_recommendations

def test_valid_https_url():
    details = normalize_and_parse_url("https://example.com/login?token=abc")
    assert details["scheme"] == "https"
    assert details["hostname"] == "example.com"
    assert details["domain"] == "example.com"
    assert details["path"] == "/login"
    assert details["query"] == "token=abc"
    assert details["has_ip"] is False

def test_missing_scheme_defaults_to_https():
    details = normalize_and_parse_url("github.com/torvalds/linux")
    assert details["scheme"] == "https"
    assert details["hostname"] == "github.com"
    assert details["normalized_url"].startswith("https://")

def test_valid_http_url():
    details = normalize_and_parse_url("http://insecure-site.org")
    assert details["scheme"] == "http"
    assert details["hostname"] == "insecure-site.org"

def test_unsupported_schemes_rejected():
    dangerous_urls = [
        "javascript:alert(1)",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "file:///etc/passwd",
        "blob:https://example.com/uuid",
        "vbscript:msgbox(1)"
    ]
    for d_url in dangerous_urls:
        with pytest.raises(ValueError) as excinfo:
            normalize_and_parse_url(d_url)
        assert "Unsupported or dangerous" in str(excinfo.value) or "Unsupported URL scheme" in str(excinfo.value)

def test_malformed_urls_rejected():
    malformed = ["", "   ", "http://", "https:///"]
    for m in malformed:
        with pytest.raises(ValueError):
            normalize_and_parse_url(m)

def test_ip_address_detection():
    # IPv4
    is_ip, ip_type = is_ip_address("192.168.1.100")
    assert is_ip is True
    assert "IPv4" in ip_type

    # IPv6
    is_ip6, ip6_type = is_ip_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
    assert is_ip6 is True
    assert "IPv6" in ip6_type

    # Regular domain is not IP
    is_ip_domain, _ = is_ip_address("paypal.com")
    assert is_ip_domain is False

def test_brand_impersonation_detection():
    details = normalize_and_parse_url("https://paypal-security-update.com/verify-account")
    indicators = run_heuristics(details)
    detected_ids = {i["id"]: i for i in indicators if i["status"] == "detected"}
    assert "brand_impersonation" in detected_ids
    assert detected_ids["brand_impersonation"]["severity"] in ("critical", "high")

def test_punycode_homoglyph_detection():
    details = normalize_and_parse_url("https://xn--e1afmkfd.xn--p1ai/auth")
    indicators = run_heuristics(details)
    detected_ids = {i["id"]: i for i in indicators if i["status"] == "detected"}
    assert "punycode_homoglyph" in detected_ids
    assert detected_ids["punycode_homoglyph"]["severity"] == "high"

def test_long_url_detection():
    long_url = "https://example.com/" + "a" * 150
    details = normalize_and_parse_url(long_url)
    indicators = run_heuristics(details)
    detected_ids = {i["id"]: i for i in indicators if i["status"] == "detected"}
    assert "url_length" in detected_ids

def test_shortener_detection():
    details = normalize_and_parse_url("https://bit.ly/3xyz45")
    indicators = run_heuristics(details)
    detected_ids = {i["id"]: i for i in indicators if i["status"] == "detected"}
    assert "url_shortener" in detected_ids

def test_userinfo_at_symbol_detection():
    details = normalize_and_parse_url("http://google.com@evil-attacker.ru/login")
    indicators = run_heuristics(details)
    detected_ids = {i["id"]: i for i in indicators if i["status"] == "detected"}
    assert "userinfo_spoofing" in detected_ids

def test_risk_score_bounds_and_levels():
    # Clean indicators
    details = normalize_and_parse_url("https://wikipedia.org/wiki/Computer_security")
    indicators = run_heuristics(details)
    threat_intel = {"checked": False, "status": "not_configured", "matches": []}
    score, level, summary = calculate_risk_score(indicators, threat_intel)
    assert 0 <= score <= 24
    assert level == "low"

    # Critical indicators (Brand impersonation + raw IP + executable)
    details_crit = normalize_and_parse_url("http://192.168.1.50/paypal-update/security.exe")
    indicators_crit = run_heuristics(details_crit)
    score_crit, level_crit, summary_crit = calculate_risk_score(indicators_crit, threat_intel)
    assert 75 <= score_crit <= 100
    assert level_crit == "critical"

    # Threat intel detected overrides score to critical
    threat_intel_bad = {"checked": True, "status": "threat_detected", "matches": ["MALWARE"]}
    score_ti, level_ti, _ = calculate_risk_score(indicators, threat_intel_bad)
    assert score_ti >= 90
    assert level_ti == "critical"

def test_recommendations_generation():
    details = normalize_and_parse_url("http://192.168.1.1/paypal/login.exe")
    indicators = run_heuristics(details)
    threat_intel = {"checked": False, "status": "not_configured", "matches": []}
    recs = generate_recommendations("critical", indicators, threat_intel)
    assert len(recs) > 0
    assert any("Brand Deception" in r or "IP addresses" in r or "Malware Delivery" in r for r in recs)
