import re
import math
import ipaddress
import urllib.parse
import tldextract
from typing import Tuple, Dict, Any, Optional

# Pre-initialize offline tldextract extractor to ensure no network calls are made
extractor = tldextract.TLDExtract(suffix_list_urls=None, cache_dir=False)

DISALLOWED_SCHEMES = {
    "javascript", "data", "file", "vbscript", "blob", "about", "filesystem", "chrome", "edge"
}

def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy for a given string."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    counts = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    for count in counts.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return round(entropy, 3)

def is_ip_address(hostname: str) -> Tuple[bool, Optional[str]]:
    """
    Detect whether a hostname is an IPv4 or IPv6 address, including decimal/hex representations.
    Returns (is_ip, ip_type).
    """
    if not hostname:
        return False, None
    
    clean_host = hostname.strip("[]")
    
    # 1. Standard IP validation via ipaddress module
    try:
        ip_obj = ipaddress.ip_address(clean_host)
        return True, f"IPv{ip_obj.version}"
    except ValueError:
        pass

    # 2. Check for numeric/decimal IP format (e.g. 2130706433)
    if clean_host.isdigit():
        try:
            val = int(clean_host)
            if 0 <= val <= 0xFFFFFFFF:
                ip_obj = ipaddress.IPv4Address(val)
                return True, "IPv4 (Decimal)"
        except ValueError:
            pass

    # 3. Check for hex/octal dotted IP notation (e.g. 0x7f.0.0.1 or 0177.0.0.1)
    parts = clean_host.split(".")
    if len(parts) == 4:
        is_num_parts = True
        octets = []
        for p in parts:
            try:
                if p.startswith(("0x", "0X")):
                    val = int(p, 16)
                elif p.startswith("0") and len(p) > 1 and p.isdigit():
                    val = int(p, 8)
                elif p.isdigit():
                    val = int(p, 10)
                else:
                    is_num_parts = False
                    break
                if 0 <= val <= 255:
                    octets.append(val)
                else:
                    is_num_parts = False
                    break
            except ValueError:
                is_num_parts = False
                break
        if is_num_parts and len(octets) == 4:
            return True, "IPv4 (Obfuscated/Hex/Octal)"

    return False, None

def normalize_and_parse_url(raw_url: str) -> Dict[str, Any]:
    """
    Normalizes and validates a URL, extracting its structural components safely.
    Raises ValueError with explanatory messages if the URL is malformed or uses unsupported schemes.
    """
    if not raw_url or not isinstance(raw_url, str):
        raise ValueError("URL must be a non-empty string.")

    cleaned_url = raw_url.strip()
    
    if len(cleaned_url) > 2048:
        raise ValueError("URL exceeds maximum permissible length of 2048 characters.")

    # Check for disallowed schemes early
    lower_check = cleaned_url.lower()
    for scheme in DISALLOWED_SCHEMES:
        if lower_check.startswith(f"{scheme}:"):
            raise ValueError(f"Unsupported or dangerous URL scheme '{scheme}:'. LinkLens only analyzes HTTP and HTTPS protocols.")

    # If scheme is missing, prepend https://
    has_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", cleaned_url))
    if not has_scheme:
        if cleaned_url.startswith("//"):
            normalized_url = "https:" + cleaned_url
        else:
            normalized_url = "https://" + cleaned_url
    else:
        normalized_url = cleaned_url

    try:
        parsed = urllib.parse.urlsplit(normalized_url)
    except Exception as exc:
        raise ValueError(f"Malformed URL structure: {str(exc)}")

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"Unsupported URL scheme '{scheme}'. Only HTTP and HTTPS are supported.")

    netloc = parsed.netloc
    if not netloc:
        raise ValueError("URL does not contain a valid network location (hostname).")

    # Handle userinfo if present in netloc (e.g. user:pass@host)
    has_userinfo = "@" in netloc
    hostname_raw = netloc.split("@")[-1]
    
    # Extract port if present
    port = None
    if ":" in hostname_raw and not hostname_raw.endswith("]"):
        # For IPv6, the colon might be inside brackets
        host_candidate, _, port_str = hostname_raw.rpartition(":")
        if host_candidate and port_str.isdigit():
            hostname_raw = host_candidate
            port = int(port_str)

    hostname = hostname_raw.strip("[]").lower()

    if not hostname:
        raise ValueError("URL does not contain a valid hostname.")

    # Check for invalid characters in hostname
    if any(c in hostname for c in (" ", "\t", "\r", "\n", "\\", "<", ">", '"', "'")):
        raise ValueError("Hostname contains illegal characters.")

    has_ip, ip_type = is_ip_address(hostname)

    # Punycode / IDN check
    is_punycode = "xn--" in hostname
    has_unicode = any(ord(c) > 127 for c in hostname)

    # Extract domain using Public Suffix List
    ext = extractor(hostname)
    domain_name = ext.domain
    suffix = ext.suffix
    subdomain = ext.subdomain

    registrable_domain = f"{domain_name}.{suffix}" if (domain_name and suffix) else hostname
    subdomain_parts = [p for p in subdomain.split(".") if p] if subdomain else []
    subdomain_count = len(subdomain_parts)

    entropy = calculate_entropy(hostname)

    return {
        "submitted_url": raw_url,
        "normalized_url": normalized_url,
        "scheme": scheme,
        "netloc": netloc,
        "hostname": hostname,
        "domain": registrable_domain,
        "subdomain": subdomain,
        "subdomain_parts": subdomain_parts,
        "subdomain_count": subdomain_count,
        "tld": suffix,
        "path": parsed.path or "/",
        "query": parsed.query,
        "fragment": parsed.fragment,
        "port": port,
        "url_length": len(normalized_url),
        "hostname_length": len(hostname),
        "has_ip": has_ip,
        "ip_type": ip_type,
        "is_punycode": is_punycode,
        "has_unicode": has_unicode,
        "has_userinfo": has_userinfo,
        "entropy": entropy,
    }
