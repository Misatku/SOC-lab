import argparse
import json
import os

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
DECISION_FILE = os.path.join(OUTPUT_DIR, "decision.json")


def determine_severity(vt_score, abuse_score):
    if vt_score >= 5 or abuse_score >= 70:
        return "HIGH", "Escalate immediately and initiate containment"
    elif vt_score > 0 or abuse_score >= 30:
        return "MEDIUM", "Continue investigation and correlate with additional evidence"
    else:
        return "LOW", "Monitor and document; no immediate escalation required"


def main():
    parser = argparse.ArgumentParser(description="Categorise enriched incident")
    parser.add_argument("--input", required=True, help="Path to enrichment JSON file")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        enrichment = json.load(f)

    vt_ip = enrichment.get("virustotal", {}).get("ip_detections", 0)
    vt_domain = enrichment.get("virustotal", {}).get("domain_detections", 0)
    abuse_score = enrichment.get("abuseipdb", {}).get("score", 0)

    vt_total = max(vt_ip, vt_domain)

    severity, action = determine_severity(vt_total, abuse_score)

    rationale = []

    if vt_total >= 5:
        rationale.append(f"VirusTotal detections are high ({vt_total})")
    elif vt_total > 0:
        rationale.append(f"VirusTotal detections greater than zero ({vt_total})")
    else:
        rationale.append("VirusTotal did not report significant detections")

    if abuse_score >= 70:
        rationale.append(f"AbuseIPDB score is high ({abuse_score})")
    elif abuse_score >= 30:
        rationale.append(f"AbuseIPDB score indicates moderate suspicion ({abuse_score})")
    else:
        rationale.append(f"AbuseIPDB score is low ({abuse_score})")

    decision = {
        "severity": severity,
        "recommended_action": action,
        "rationale": rationale
    }

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    with open(DECISION_FILE, "w", encoding="utf-8") as f:
        json.dump(decision, f, indent=2)

    print(f"[+] Decision written to: {DECISION_FILE}")


if __name__ == "__main__":
    main()