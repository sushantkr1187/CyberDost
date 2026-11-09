"""
Automated Threat Feed Ingestion & Reputation Lookup
Integrates with URLhaus (abuse.ch) public API.
"""

from typing import Any, Dict
import httpx

URLHAUS_API_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"


async def check_urlhaus(target_url: str) -> Dict[str, Any]:
    """Queries URLhaus API to check if target URL is a known malicious threat."""
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            response = await client.post(
                URLHAUS_API_ENDPOINT, data={"url": target_url}
            )

            if response.status_code == 200:
                data = response.json()
                query_status = data.get("query_status")

                if query_status == "ok":
                    return {
                        "is_blacklisted": True,
                        "feed_name": "URLhaus (abuse.ch)",
                        "threat_type": data.get("threat", "malware_phishing"),
                        "threat_status": data.get("url_status", "active"),
                        "reporter": data.get("reporter", "community"),
                        "date_added": data.get("date_added", "unknown"),
                    }
    except Exception:
        # Failsafe on network timeout or feed downtime
        pass

    return {
        "is_blacklisted": False,
        "feed_name": "URLhaus (abuse.ch)",
        "threat_type": None,
        "threat_status": None,
        "reporter": None,
        "date_added": None,
    }
