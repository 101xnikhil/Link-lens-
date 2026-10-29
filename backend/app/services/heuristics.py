import re
import urllib.parse
from typing import Dict, Any, List, Tuple

# Popular high-profile targets for brand spoofing
TARGET_BRANDS = [
    "paypal", "apple", "google", "microsoft", "amazon", "netflix",
    "facebook", "instagram", "chase", "bankofamerica", "wellsfargo",
    "citibank", "coinbase", "binance", "metamask", "steam",
    "dropbox", "yahoo", "outlook", "linkedin", "twitter", "whatsapp"
]

# Common URL shorteners
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
    "cutt.ly", "rebrand.ly", "bl.ink", "shorturl.at", "tiny.cc",
    "rb.gy", "v.gd", "soo.gd", "qr.ae"
}

# TLDs frequently associated with disposable, spam, or phishing campaigns
SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "click", "fit", "gq", "tk", "ml", "cf", "ga",
    "rest", "ru", "su", "zip", "mov", "buzz", "cn", "cam", "loan", "surf"
}

# High-risk keywords associated with credential harvesting and phishing lures
CREDENTIAL_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "account", "banking", "password", "secure", "security", "update",
    "wallet", "recover", "recovery", "credential", "authentication",
    "confirm", "confirmation", "session", "suspended", "unlock",
    "billing", "invoice", "validate", "support"
]

# Dangerous file extensions
EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".msi", ".jar", ".apk",
    ".ps1", ".hta", ".iso", ".pif", ".wsf"
}

# Redirect parameters
REDIRECT_PARAMS = [
    "url", "redirect", "redir", "next", "dest", "destination", "target",
    "link", "r", "return", "forward", "goto"
]

def check_ip_hostname(details: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    has_ip = details.get("has_ip", False)
    ip_type = details.get("ip_type")
    if has_ip:
        return True, {
            "id": "ip_as_hostname",
            "name": "Direct IP Address in Hostname",
            "category": "domain",
            "severity": "high",
            "status": "detected",
            "weight": 35,
            "explanation": f"The URL uses a raw IP address ({details['hostname']} - {ip_type}) instead of a verified registered domain. Legitimate services almost universally use domain names with trusted certificates.",
            "recommended_action": "Avoid visiting websites addressed solely by raw IP numbers, especially if requesting credentials or downloads."
        }
    return False, {
        "id": "ip_as_hostname",
        "name": "Standard Domain Hostname",
        "category": "domain",
        "severity": "info",
        "status": "clean",
        "weight": 0,
        "explanation": "The URL uses a standard textual hostname rather than a raw IP address.",
        "recommended_action": "No immediate action required on this indicator."
    }

def check_url_length(details: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    length = details.get("url_length", 0)
    if length > 120:
        return True, {
            "id": "url_length",
            "name": "Excessively Long URL",
            "category": "structure",
            "severity": "medium",
            "status": "detected",
            "weight": 18,
            "explanation": f"The URL is unusually long ({length} characters). Phishers frequently generate lengthy URLs to hide malicious destination components or mimic complex legitimate routing.",
            "recommended_action": "Inspect the domain and path segments carefully before entering sensitive data."
        }
    elif length > 75:
        return True, {
            "id": "url_length",
            "name": "Moderately Long URL",
            "category": "structure",
            "severity": "low",
            "status": "detected",
            "weight": 8,
            "explanation": f"The URL has above-average length ({length} characters). While common for deep links, it warrants awareness.",
            "recommended_action": "Verify that the base domain matches the anticipated service."
        }
    return False, {
        "id": "url_length",
        "name": "Normal URL Length",
        "category": "structure",
        "severity": "info",
        "status": "clean",
        "weight": 0,
        "explanation": f"The URL length ({length} characters) is within standard operational ranges.",
        "recommended_action": "No action required."
    }

def check_shortener(details: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    hostname = details.get("hostname", "").lower()
    domain = details.get("domain", "").lower()
    is_shortener = hostname in SHORTENER_DOMAINS or domain in SHORTENER_DOMAINS
    details["is_shortened"] = is_shortener
    if is_shortener:
        return True, {
            "id": "url_shortener",
            "name": "Known URL Shortening Service",
            "category": "structure",
            "severity": "medium",
            "status": "detected",
            "weight": 22,
            "explanation": f"The URL uses a public shortening service ({domain}). Shortened links obscure the final destination domain and are heavily leveraged in social engineering attacks.",
            "recommended_action": "Use an unshortening inspection tool to reveal the final destination before interacting with the page."
        }
    return False, {
        "id": "url_shortener",
        "name": "Direct Destination Domain",
        "category": "structure",
        "severity": "info",
        "status": "clean",
        "weight": 0,
        "explanation": "The URL specifies a direct target domain rather than concealing it behind a known link shortener.",
        "recommended_action": "No action required."
    }

def check_subdomains(details: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    count = details.get("subdomain_count", 0)
    subdomain = details.get("subdomain", "")
    if count >= 3:
        return True, {
            "id": "excessive_subdomains",
            "name": "Excessive Subdomain Stacking",
            "category": "domain",
            "severity": "high",
            "status": "detected",
            "weight": 24,
            "explanation": f"The URL contains {count} levels of subdomains ('{subdomain}'). Attackers often stack subdomains containing trusted brand names to fool users on mobile viewports.",
            "recommended_action": "Look exclusively at the rightmost domain before the top-level suffix to identify the actual host."
        }
    elif count == 2:
        return True, {
            "id": "excessive_subdomains",
            "name": "Multiple Subdomains",
            "category": "domain",
            "severity": "low",
            "status": "detected",
            "weight": 7,
            "explanation": f"The URL has multiple subdomain levels ('{subdomain}'). This can be normal for large enterprise systems, but is also seen in obfuscation tactics.",
            "recommended_action": "Confirm the organizational identity of the primary domain."
        }
    return False, {
        "id": "excessive_subdomains",
        "name": "Standard Subdomain Hierarchy",
        "category": "domain",
        "severity": "info",
        "status": "clean",
        "weight": 0,
        "explanation": "Subdomain depth is within conventional bounds.",
        "recommended_action": "No action required."
    }

def check_brand_impersonation(details: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    hostname = details.get("hostname", "").lower()
    domain = details.get("domain", "").lower()
    subdomain = details.get("subdomain", "").lower()
    path = details.get("path", "").lower()

    # Look for known brand names in subdomains or non-official domains
    matched_brands = []
    for brand in TARGET_BRANDS:
        # Check if brand appears in hostname but the registered domain is NOT that brand's official domain
        if brand in hostname:
            # If domain itself is official e.g. paypal.com, google.com
            official_pattern = rf"^{brand}\.[a-z.]+$"
            if not re.match(official_pattern, domain):
                matched_brands.append(brand)
        # Also check typosquatting in domain (e.g. paypa1, micros0ft, goog1e)
        typo_patterns = [
            (brand.replace("l", "1"), brand),
            (brand.replace("o", "0"), brand),
            (brand.replace("i", "1"), brand),
            (brand.replace("m", "rn"), brand),
            (brand.replace("vv", "w"), brand)
        ]
        for typo, orig in typo_patterns:
            if typo != orig and typo in domain:
                matched_brands.append(f"{orig} (typosquatted: {typo})")

    matched_brands = list(set(matched_brands))
    if matched_brands:
        brand_list_str = ", ".join(matched_brands)
        return True, {
            "id": "brand_impersonation",
            "name": "Brand Name Incongruity / Typosquatting",
            "category": "domain",
            "severity": "critical",
            "status": "detected",
            "weight": 40,
            "explanation": f"The URL references brand name(s) [{brand_list_str}] inside subdomains or an unofficial root domain ('{domain}'). This is a classic indicator of credential harvesting and brand deception.",
            "recommended_action": "Do not log in or provide payment details. Navigate to the verified official portal independently."
        }
    return False, {
        "id": "brand_impersonation",
        "name": "No Detected Brand Misuse",
        "category": "domain",
        "severity": "info",
        "status": "clean",
        "weight": 0,
        "explanation": "No known deceptive brand impersonation or typosquatting patterns were detected in the domain components.",
        "recommended_action": "Always verify official domain ownership before authenticating."
    }

def check_credential_keywords(details: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    path = details.get("path", "").lower()
    query = details.get("query", "").lower()
    subdomain = details.get("subdomain", "").lower()
    full_search = f"{subdomain}/{path}?{query}"

    found_keywords = [kw for kw in CREDENTIAL_KEYWORDS if re.search(rf"\b{re.escape(kw)}\b|[-_/]{re.escape(kw)}[-_/]?", full_search)]
    found_keywords = list(set(found_keywords))
    details["suspicious_keywords_found"] = found_keywords

    if len(found_keywords) >= 3:
        return True, {
            "id": "suspicious_keywords",
            "name": "High Density of Credential Keywords",
            "category": "pattern",
            "severity": "high",
            "status": "detected",
            "weight": 25,
            "explanation": f"Detected multiple high-risk credential keywords ({', '.join(found_keywords[:6])}) in the URL structure. This combination is common in fake authentication portals.",
            "recommended_action": "Check your browser address bar carefully and never enter passwords on unverified sites."
        }
    elif len(found_keywords) >= 1:
        return True, {
            "id": "suspicious_keywords",
            "name": "Authentication / Security Keywords Present",
            "category": "pattern",
            "severity": "low",
            "status": "detected",
            "weight": 10,
            "explanation": f"Detected keyword(s) ({', '.join(found_keywords)}) often associated with account logins. This can be benign on authentic sites or deceptive on replicas.",
            "recommended_action": "Confirm you navigated to this login portal intentionally."
        }
    return False, {
        "id": "suspicious_keywords",
        "name": "No Sensitive Credential Lures",
        "category": "pattern",
        "severity": "info",
        "status": "clean",
        "weight": 0,
        "explanation": "URL path and parameters do not display prominent credential harvesting keywords.",
        "recommended_action": "No action required."
    }

def check_suspicious_tld(details: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    tld = details.get("tld", "").lower()
    if tld in SUSPICIOUS_TLDS:
        return True, {
            "id": "suspicious_tld",
            "name": f"High-Abuse Top-Level Domain (.{tld})",
            "category": "domain",
            "severity": "medium",
            "status": "detected",
            "weight": 20,
            "explanation": f"The top-level domain '.{tld}' is recognized in cybersecurity telemetry as having high historical abuse rates for low-cost, automated phishing disposable domains.",
            "recommended_action": "Exercise heightened scrutiny before interacting with forms or files hosted on this TLD."
        }
    return False, {
        "id": "suspicious_tld",
        "name": "Standard Top-Level Domain",
        "category": "domain",
        "severity": "info",
        "status": "clean",
        "weight": 0,
        "explanation": f"The TLD (.{tld or 'unknown'}) is not flagged on standard high-abuse domain watchlists.",
        "recommended_action": "No action required."
    }

def check_https(details: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    scheme = details.get("scheme", "").lower()
    if scheme != "https":
        return True, {
            "id": "insecure_scheme",
            "name": "Unencrypted HTTP Scheme",
            "category": "structure",
            "severity": "medium",
            "status": "detected",
            "weight": 18,
            "explanation": "The URL uses unencrypted plain HTTP instead of HTTPS. Communications can be intercepted or altered by intermediate network actors (Man-in-the-Middle). Note: HTTPS alone does not prove a site is trustworthy, but HTTP is inherently insecure for sensitive exchanges.",
            "recommended_action": "Do not enter passwords, personal identities, or payment info over unencrypted connections."
        }
    return False, {
        "id": "insecure_scheme",
        "name": "HTTPS Encryption Scheme",
        "category": "structure",
        "severity": "info",
        "status": "clean",
        "weight": 0,
        "explanation": "The URL specifies transport encryption (HTTPS). Note that HTTPS verifies transport security, not business legitimacy.",
        "recommended_action": "Ensure valid SSL certificates are presented when your browser loads the resource."
    }

def check_non_standard_port(details: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    port = details.get("port")
    scheme = details.get("scheme", "").lower()
    is_standard = (port is None) or (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    if not is_standard:
        return True, {
            "id": "non_standard_port",
            "name": f"Non-Standard Port ({port})",
            "category": "structure",
            "severity": "medium",
            "status": "detected",
            "weight": 16,
            "explanation": f"The URL directs connections to custom port {port} instead of standard web ports (80/443). Malicious payloads or evasion proxies often run on non-standard ports to bypass perimeter filters.",
            "recommended_action": "Verify if this service legitimately operates on an alternative port."
        }
    return False, {
        "id": "non_standard_port",
        "name": "Standard Web Port",
        "category": "structure",
        "severity": "info",
        "status": "clean",
        "weight": 0,
        "explanation": "The URL uses default web communication ports.",
        "recommended_action": "No action required."
    }

def check_url_encoding(details: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    raw_url = details.get("submitted_url", "")
    pct_count = raw_url.count("%")
    double_encoded = "%25" in raw_url.lower()
    
    if double_encoded or pct_count > 4:
        return True, {
            "id": "url_encoding_obfuscation",
            "name": "Heavy Percent-Encoding / Obfuscation",
            "category": "pattern",
            "severity": "medium",
            "status": "detected",
            "weight": 16,
            "explanation": f"Detected heavy URL percent-encoding ({pct_count} '%' tokens) or potential double-encoding. Attackers employ URL encoding to evade signature-based detection filters.",
            "recommended_action": "Decode and scrutinize the actual destination strings before trusting the resource."
        }
    return False, {
        "id": "url_encoding_obfuscation",
        "name": "Normal Character Encoding",
        "category": "pattern",
        "severity": "info",
        "status": "clean",
        "weight": 0,
        "explanation": "URL uses clean, un-obfuscated standard character sequences.",
        "recommended_action": "No action required."
    }

def check_userinfo_at_symbol(details: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    has_userinfo = details.get("has_userinfo", False)
    if has_userinfo:
        return True, {
            "id": "userinfo_spoofing",
            "name": "Userinfo '@' Symbol in URL",
            "category": "structure",
            "severity": "high",
            "status": "detected",
            "weight": 30,
            "explanation": "The URL contains an '@' character before the destination host. Browsers ignore everything before '@' as user credentials, allowing attackers to display a deceptive trusted domain (e.g., http://google.com@malicious.com).",
            "recommended_action": "Do not open this URL; it is designed to mislead users regarding its true host destination."
        }
    return False, {
        "id": "userinfo_spoofing",
        "name": "No Userinfo Misdirection",
        "category": "structure",
        "severity": "info",
        "status": "clean",
        "weight": 0,
        "explanation": "No '@' character used to obscure the true hostname.",
        "recommended_action": "No action required."
    }

def check_punycode_unicode(details: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    is_puny = details.get("is_punycode", False)
    has_uni = details.get("has_unicode", False)
    if is_puny or has_uni:
        return True, {
            "id": "punycode_homoglyph",
            "name": "Punycode / IDN Homoglyph Risk",
            "category": "domain",
            "severity": "high",
            "status": "detected",
            "weight": 28,
            "explanation": f"The hostname utilizes Punycode ('xn--') or non-ASCII Unicode characters ({details['hostname']}). Internationalized domain names can visually imitate familiar Latin letters (e.g. Cyrillic 'а' replacing Latin 'a') to deceive users.",
            "recommended_action": "Carefully inspect the decoded ASCII Punycode representation to ensure it is not an IDN homoglyph imitation."
        }
    return False, {
        "id": "punycode_homoglyph",
        "name": "Standard ASCII Domain",
        "category": "domain",
        "severity": "info",
        "status": "clean",
        "weight": 0,
        "explanation": "The hostname uses standard ASCII characters with no Punycode homoglyph flags.",
        "recommended_action": "No action required."
    }

def check_redirect_parameters(details: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    query = details.get("query", "").lower()
    detected_redirects = []
    for param in REDIRECT_PARAMS:
        if re.search(rf"[?&]{re.escape(param)}=[^&]+", f"?{query}"):
            detected_redirects.append(param)
    
    if len(detected_redirects) >= 2 or ("http://" in query or "https://" in query):
        return True, {
            "id": "open_redirect_potential",
            "name": "Multiple Redirect Parameters",
            "category": "pattern",
            "severity": "medium",
            "status": "detected",
            "weight": 18,
            "explanation": f"The URL embeds nested destination parameters ({', '.join(detected_redirects)}). Attackers frequently exploit Open Redirects on trusted domains to bounce victims to malicious third-party landing pages.",
            "recommended_action": "Check the nested parameter to identify the ultimate target destination."
        }
    return False, {
        "id": "open_redirect_potential",
        "name": "No Suspicious Redirect Parameters",
        "category": "pattern",
        "severity": "info",
        "status": "clean",
        "weight": 0,
        "explanation": "No complex embedded redirect parameter patterns detected.",
        "recommended_action": "No action required."
    }

def check_executable_extensions(details: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    path = details.get("path", "").lower()
    for ext in EXECUTABLE_EXTENSIONS:
        if path.endswith(ext) or f"{ext}?" in path:
            return True, {
                "id": "executable_download",
                "name": f"Direct Executable Extension ({ext})",
                "category": "pattern",
                "severity": "critical",
                "status": "detected",
                "weight": 35,
                "explanation": f"The URL links directly to an executable, script, or installer file ({ext}). Drive-by downloads and malware droppers commonly deliver malicious payloads directly via links.",
                "recommended_action": "Do not download or execute files from unsolicited links."
            }
    return False, {
        "id": "executable_download",
        "name": "No Direct Executable Extension",
        "category": "pattern",
        "severity": "info",
        "status": "clean",
        "weight": 0,
        "explanation": "URL does not point directly to standard executable binary formats.",
        "recommended_action": "No action required."
    }

def check_entropy(details: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    entropy = details.get("entropy", 0.0)
    # High entropy (> 4.2) often indicates algorithmic generation (DGA) or random hex strings
    if entropy > 4.2 and details.get("hostname_length", 0) > 15:
        return True, {
            "id": "high_entropy_domain",
            "name": "High Shannon Entropy (Potential DGA)",
            "category": "domain",
            "severity": "medium",
            "status": "detected",
            "weight": 18,
            "explanation": f"The hostname exhibits high randomness / Shannon entropy ({entropy:.2f}). Domain Generation Algorithms (DGAs) frequently generate random high-entropy strings for malware command-and-control.",
            "recommended_action": "Verify if the domain is known to IT security or is an auto-generated disposable address."
        }
    return False, {
        "id": "high_entropy_domain",
        "name": "Normal Domain Entropy",
        "category": "domain",
        "severity": "info",
        "status": "clean",
        "weight": 0,
        "explanation": f"Domain character distribution exhibits normal natural language entropy ({entropy:.2f}).",
        "recommended_action": "No action required."
    }

ALL_HEURISTIC_CHECKS = [
    check_ip_hostname,
    check_brand_impersonation,
    check_executable_extensions,
    check_userinfo_at_symbol,
    check_punycode_unicode,
    check_credential_keywords,
    check_subdomains,
    check_shortener,
    check_suspicious_tld,
    check_https,
    check_non_standard_port,
    check_url_encoding,
    check_redirect_parameters,
    check_url_length,
    check_entropy
]

def run_heuristics(url_details: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Executes all modular heuristic checks and returns a list of evaluated indicators.
    """
    indicators = []
    for check_fn in ALL_HEURISTIC_CHECKS:
        _, indicator = check_fn(url_details)
        indicators.append(indicator)
    return indicators
