import httpx
from typing import Dict, Any, Optional
from app.config import settings

SAFE_BROWSING_V4_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

async def check_threat_intelligence(normalized_url: str) -> Dict[str, Any]:
    """
    Queries Google Safe Browsing API v4 if an API key is configured.
    Safely degrades and returns structured status if credentials are missing or lookup fails.
    """
    api_key = settings.GOOGLE_SAFE_BROWSING_API_KEY

    # Check if API key is not configured
    if not api_key:
        return {
            "checked": False,
            "status": "not_configured",
            "provider": "Google Safe Browsing v4",
            "details": "External threat intelligence key not configured. Security assessment is grounded solely in local heuristic and structural signal analysis.",
            "matches": []
        }

    payload = {
        "client": {
            "clientId": "linklens-security-analyzer",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": normalized_url}
            ]
        }
    }

    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            response = await client.post(
                f"{SAFE_BROWSING_V4_URL}?key={api_key}",
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                data = response.json()
                matches = data.get("matches", [])
                if matches:
                    threat_types = list({m.get("threatType", "UNKNOWN_THREAT") for m in matches})
                    return {
                        "checked": True,
                        "status": "threat_detected",
                        "provider": "Google Safe Browsing v4",
                        "details": f"Flagged by threat intelligence registry for: {', '.join(threat_types)}.",
                        "matches": threat_types
                    }
                else:
                    return {
                        "checked": True,
                        "status": "clean",
                        "provider": "Google Safe Browsing v4",
                        "details": "No active threat matches found in verified global threat intelligence database.",
                        "matches": []
                    }
            elif response.status_code == 400:
                return {
                    "checked": False,
                    "status": "lookup_failed",
                    "provider": "Google Safe Browsing v4",
                    "details": "Threat intelligence service returned HTTP 400 (Invalid key or request parameters).",
                    "matches": []
                }
            elif response.status_code == 403:
                return {
                    "checked": False,
                    "status": "lookup_failed",
                    "provider": "Google Safe Browsing v4",
                    "details": "Threat intelligence API key lacks required permissions or quota exceeded.",
                    "matches": []
                }
            else:
                return {
                    "checked": False,
                    "status": "lookup_failed",
                    "provider": "Google Safe Browsing v4",
                    "details": f"Threat intelligence lookup returned HTTP {response.status_code}.",
                    "matches": []
                }
    except httpx.TimeoutException:
        return {
            "checked": False,
            "status": "lookup_failed",
            "provider": "Google Safe Browsing v4",
            "details": "Threat intelligence request timed out after 4.0 seconds. Assessment proceeded with heuristic signals.",
            "matches": []
        }
    except Exception as exc:
        return {
            "checked": False,
            "status": "lookup_failed",
            "provider": "Google Safe Browsing v4",
            "details": f"Threat intelligence connection encountered an error: {str(exc)}.",
            "matches": []
        }
