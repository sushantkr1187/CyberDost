"""
Visual Phishing & Brand Impersonation Detector
Uses Perceptual Hashing (pHash) and Hamming Distance comparison.
"""

import io
from typing import Any, Dict, List
import imagehash
from PIL import Image

# Pre-computed baseline perceptual hashes of common target portals.
# A Hamming distance <= 10 indicates high visual similarity / template clone.
REFERENCE_BRAND_PHASHES: Dict[str, str] = {
    "Google Account Login": "d1c238b9e0f34a12",
    "Microsoft 365 Login": "f8a03c21b9d4e567",
    "State Bank of India (SBI)": "a3b4c5d6e7f80123",
    "ICICI Bank NetBanking": "b9c8d7e6f5a43210",
    "PayPal Authentication": "e4f5a6b7c8d90123",
}


def analyze_screenshot_phash(
    screenshot_bytes: bytes, hamming_threshold: int = 10
) -> Dict[str, Any]:
    """Analyzes a raw browser viewport screenshot against known brand login pages."""
    try:
        image = Image.open(io.BytesIO(screenshot_bytes))
        computed_phash = imagehash.phash(image)

        matches: List[Dict[str, Any]] = []

        for brand_name, ref_hash_str in REFERENCE_BRAND_PHASHES.items():
            ref_hash = imagehash.hex_to_hash(ref_hash_str)
            hamming_distance = computed_phash - ref_hash

            if hamming_distance <= hamming_threshold:
                # 0 diff = 100% visual match; 10 diff = ~84% visual match
                similarity_pct = round((1 - (hamming_distance / 64.0)) * 100, 2)
                matches.append(
                    {
                        "brand": brand_name,
                        "hamming_distance": hamming_distance,
                        "visual_similarity_score": similarity_pct,
                    }
                )

        matches.sort(key=lambda item: item["hamming_distance"])

        return {
            "visual_phishing_detected": len(matches) > 0,
            "page_phash": str(computed_phash),
            "matched_brands": matches,
        }

    except Exception as exc:
        return {
            "visual_phishing_detected": False,
            "page_phash": None,
            "matched_brands": [],
            "error": str(exc),
        }
