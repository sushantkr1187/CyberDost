"""
Network Infrastructure & Autonomous System (ASN) Profiler
Resolves IP, ASN name, CIDR prefix, and hosting telemetry via RDAP.
"""

from typing import Any, Dict
from urllib.parse import urlparse
import socket
from ipwhois import IPWhois


def extract_domain(target: str) -> str:
    """Normalizes raw input or URL into a clean FQDN hostname."""
    if "://" not in target:
        target = "http://" + target
    parsed = urlparse(target)
    hostname = parsed.hostname or target
    return hostname.strip()


def profile_infrastructure(target: str) -> Dict[str, Any]:
    """Inspects IP, ASN, Hosting ISP, and country routing telemetry."""
    domain = extract_domain(target)

    try:
        resolved_ip = socket.gethostbyname(domain)
    except socket.gaierror as e:
        return {
            "domain": domain,
            "resolved_ip": None,
            "asn": None,
            "asn_description": None,
            "asn_cidr": None,
            "country": None,
            "error": f"DNS resolution failed: {str(e)}",
        }

    try:
        ip_analyzer = IPWhois(resolved_ip)
        rdap_results = ip_analyzer.lookup_rdap(depth=1)

        asn = rdap_results.get("asn")
        asn_desc = rdap_results.get("asn_description", "Unknown Provider")
        asn_cidr = rdap_results.get("asn_cidr", "N/A")
        country = rdap_results.get("asn_country_code", "Unknown")

        return {
            "domain": domain,
            "resolved_ip": resolved_ip,
            "asn": asn,
            "asn_description": asn_desc,
            "asn_cidr": asn_cidr,
            "country": country,
            "error": None,
        }
    except Exception as exc:
        return {
            "domain": domain,
            "resolved_ip": resolved_ip,
            "asn": None,
            "asn_description": None,
            "asn_cidr": None,
            "country": None,
            "error": f"ASN RDAP lookup failed: {str(exc)}",
        }
