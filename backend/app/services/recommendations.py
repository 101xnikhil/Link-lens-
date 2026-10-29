from typing import List, Dict, Any

def generate_recommendations(
    risk_level: str,
    indicators: List[Dict[str, Any]],
    threat_intel: Dict[str, Any]
) -> List[str]:
    """
    Generates tailored, actionable security recommendations based on detected signals.
    """
    recs: List[str] = []
    detected_ids = {ind.get("id") for ind in indicators if ind.get("status") == "detected"}

    # Threat intel triggered
    if threat_intel.get("status") == "threat_detected":
        recs.append("BLOCK / DO NOT VISIT: This URL is explicitly identified in global threat intelligence registries as malicious.")
        recs.append("If you have already visited this link or entered credentials, change your passwords immediately and run an antivirus scan.")

    # High severity indicators
    if "brand_impersonation" in detected_ids:
        recs.append("Brand Deception Alert: Do NOT enter credentials or payment info. Open a new browser tab and navigate to the verified official website directly.")
    
    if "ip_as_hostname" in detected_ids:
        recs.append("Avoid connecting to services addressed purely by numeric IP addresses; legitimate corporate platforms rely on verified domain certificates.")

    if "executable_download" in detected_ids:
        recs.append("Malware Delivery Warning: Do not accept or execute downloaded files (.exe, .scr, .apk) originated from this link.")

    if "userinfo_spoofing" in detected_ids:
        recs.append("Deceptive URL structure detected using the '@' symbol. The actual host is different from the apparent brand name.")

    if "punycode_homoglyph" in detected_ids:
        recs.append("Punycode / Homoglyph Detected: Check character encodings closely to ensure letters are not lookalikes from foreign alphabets.")

    if "url_shortener" in detected_ids:
        recs.append("Shortened link detected: Use a link previewer or unshortening service to inspect the final landing destination before opening.")

    if "insecure_scheme" in detected_ids:
        recs.append("Unencrypted connection (HTTP): Never transmit personal data, passwords, or banking details over unencrypted channels.")

    if "suspicious_keywords" in detected_ids:
        recs.append("Verify the URL in your browser's address bar before authenticating to ensure you are on the authentic authentication portal.")

    # Always reinforce fundamental security advice
    if risk_level in ("critical", "high"):
        recs.append("Report this URL to your IT security administrator or browser anti-phishing provider (e.g. Google Safe Browsing / Microsoft SmartScreen).")
    
    recs.append("Remember: Never assume HTTPS alone guarantees legitimacy—cybercriminals routinely secure phishing sites with free SSL certificates.")
    recs.append("When in doubt, independently verify with the alleged sender via a separate, trusted communication channel.")

    # Deduplicate while preserving order
    seen = set()
    unique_recs = []
    for r in recs:
        if r not in seen:
            seen.add(r)
            unique_recs.append(r)

    return unique_recs[:6]
