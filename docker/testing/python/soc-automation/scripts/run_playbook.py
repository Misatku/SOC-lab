import argparse
import subprocess
import os
import json

# ===== PATH SETUP =====
BASE_DIR = os.path.dirname(os.path.dirname(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "output")

ENRICH_SCRIPT = os.path.join(BASE_DIR, "scripts", "enrich_alert.py")
CATEGORISE_SCRIPT = os.path.join(BASE_DIR, "scripts", "categorise_incident.py")

ENRICHMENT_FILE = os.path.join(OUTPUT_DIR, "enrichment.json")
DECISION_FILE = os.path.join(OUTPUT_DIR, "decision.json")


def run_enrichment(ip, domain):
    print("\n[+] Running enrichment...")

    cmd = [
        "python",
        ENRICH_SCRIPT,
        "--ip", ip,
        "--domain", domain
    ]

    subprocess.run(cmd, check=True)


def run_categorisation():
    print("\n[+] Running categorisation...")

    cmd = [
        "python",
        CATEGORISE_SCRIPT,
        "--input", ENRICHMENT_FILE
    ]

    subprocess.run(cmd, check=True)


def display_results():
    print("\n========== INCIDENT SUMMARY ==========")

    if not os.path.exists(DECISION_FILE):
        print("❌ No decision file found.")
        return

    with open(DECISION_FILE, "r") as f:
        decision = json.load(f)

    print(f"\nSeverity: {decision.get('severity')}")
    print(f"Recommended Action: {decision.get('recommended_action')}")

    print("\nRationale:")
    for reason in decision.get("rationale", []):
        print(f" - {reason}")

    print("\n======================================\n")


def main():
    parser = argparse.ArgumentParser(description="SOC Automation Playbook Runner")
    parser.add_argument("--ip", required=True, help="IP address to analyse")
    parser.add_argument("--domain", required=True, help="Domain to analyse")

    args = parser.parse_args()

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    run_enrichment(args.ip, args.domain)
    run_categorisation()
    display_results()


if __name__ == "__main__":
    main()