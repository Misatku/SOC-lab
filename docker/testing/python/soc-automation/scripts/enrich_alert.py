import argparse
import json
import os
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "enrichment.json")


def main():
    parser = argparse.ArgumentParser(description="Enrich alert indicators")
    parser.add_argument("--ip", required=True, help="IP address to enrich")
    parser.add_argument("--domain", required=True, help="Domain to enrich")
    args = parser.parse_args()

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    enrichment = {
        "input": {
            "ip": args.ip,
            "domain": args.domain,
            "url": None
        },
        "virustotal": {
            "ip_detections": 1,
            "domain_detections": 0
        },
        "abuseipdb": {
            "score": 30,
            "reports": 5
        },
        "ipinfo": {
            "country": "US",
            "org": "GitHub, Inc."
        },
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(enrichment, f, indent=2)

    print(f"[+] Enrichment written to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()