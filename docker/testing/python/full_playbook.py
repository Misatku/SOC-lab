from thehive4py import TheHiveApi
import requests
import urllib3
import time
import json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===== CONFIG =====
THEHIVE_URL = "https://localhost/thehive"
API_KEY = "zpbHIYwLsaBUSNZLGh97pFn0G3koQdoe"
CORTEX_ID = "Cortex-1"

api = TheHiveApi(THEHIVE_URL, API_KEY)
api.session.verify = False
requests.packages.urllib3.disable_warnings()

source_ref = f"alert-{int(time.time())}"

# ===== CREATE ALERT =====
alert_data = {
    "title": "Automated phishing alert",
    "description": "Automatically generated phishing alert from a simulated email security source.",
    "type": "external",
    "source": "soc-demo",
    "sourceRef": source_ref,
    "severity": 2,
    "tlp": 2,
    "tags": ["phishing", "automation", "email-alert"]
}

alert_response = api.alert.create(alert_data)
print("[DEBUG] Alert response:", alert_response)

alert_id = alert_response.get("id") or alert_response.get("_id")
if not alert_id:
    raise SystemExit("Failed to create alert")

print(f"[+] Alert created: {alert_id}")

# ===== ADD OBSERVABLES TO ALERT =====
observables = [
    {
        "dataType": "ip",
        "data": "185.199.110.153",
        "ioc": True,
        "tlp": 2,
        "tags": ["suspicious", "external-ip"]
    },
    {
        "dataType": "domain",
        "data": "login-security-check.com",
        "ioc": True,
        "tlp": 2,
        "tags": ["phishing", "suspicious-domain"]
    },
    {
        "dataType": "mail",
        "data": "user.account@example.com",
        "ioc": False,
        "tlp": 2,
        "tags": ["victim"]
    }
]

for obs in observables:
    obs_response = api.observable.create_in_alert(alert_id, obs)
    print(f"[+] Added alert observable: {obs['data']}")
    print("[DEBUG]", obs_response)

# ===== PROMOTE ALERT TO CASE =====
promote_response = api.alert.promote_to_case(alert_id)
print("[DEBUG] Promote response:", promote_response)

case_id = None

if isinstance(promote_response, dict):
    case_id = promote_response.get("id") or promote_response.get("_id")

if not case_id and isinstance(promote_response, dict):
    case_obj = promote_response.get("case")
    if isinstance(case_obj, dict):
        case_id = case_obj.get("id") or case_obj.get("_id")

if not case_id:
    raise SystemExit("Failed to get case ID after promoting alert")

print(f"[+] Case created: {case_id}")

# ===== GET CASE OBSERVABLES =====
observable_list = []
max_retries = 10

for i in range(max_retries):
    print(f"[DEBUG] Checking for case observables (attempt {i+1})...")

    case_observables = api.case.find_observables(case_id)

    if isinstance(case_observables, dict):
        observable_list = case_observables.get("data", [])
    else:
        observable_list = case_observables

    if observable_list:
        print("[+] Observables found in case")
        break

    time.sleep(2)

if not observable_list:
    raise SystemExit("No observables found in case after waiting")

print("[DEBUG] Case observables:", observable_list)

# ===== EXTRACT CASE OBSERVABLE IDS =====
ip_observable_id = None
domain_observable_id = None
mail_observable_id = None

for obs in observable_list:
    if obs.get("dataType") == "ip" and obs.get("data") == "185.199.110.153":
        ip_observable_id = obs.get("id") or obs.get("_id")
    if obs.get("dataType") == "domain" and obs.get("data") == "login-security-check.com":
        domain_observable_id = obs.get("id") or obs.get("_id")
    if obs.get("dataType") == "mail" and obs.get("data") == "user.account@example.com":
        mail_observable_id = obs.get("id") or obs.get("_id")

print(f"[+] Case IP observable ID: {ip_observable_id}")
print(f"[+] Case domain observable ID: {domain_observable_id}")
print(f"[+] Case mail observable ID: {mail_observable_id}")

if not ip_observable_id:
    raise SystemExit("IP observable not found in case")

# ===== RUN ANALYZERS =====
headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

job_url = f"{THEHIVE_URL}/api/v1/connector/cortex/job"

# IP analyzers
ip_analyzers = [
    "AbuseIPDB_2_0",
    "IPinfo_Details_1_0",
    "VirusTotal_GetReport_3_1"
]

for analyzer in ip_analyzers:
    payload = {
        "analyzerId": analyzer,
        "artifactId": ip_observable_id,
        "cortexId": CORTEX_ID
    }

    response = requests.post(job_url, headers=headers, json=payload, verify=False)

    print(f"\n[+] Running analyzer on IP: {analyzer}")
    print("Status:", response.status_code)

    try:
        print(json.dumps(response.json(), indent=2))
    except Exception:
        print(response.text)

# Domain analyzer
if domain_observable_id:
    payload = {
        "analyzerId": "VirusTotal_GetReport_3_1",
        "artifactId": domain_observable_id,
        "cortexId": CORTEX_ID
    }

    response = requests.post(job_url, headers=headers, json=payload, verify=False)

    print(f"\n[+] Running analyzer on domain: VirusTotal_GetReport_3_1")
    print("Status:", response.status_code)

    try:
        print(json.dumps(response.json(), indent=2))
    except Exception:
        print(response.text)

# Mail analyzers
if mail_observable_id:
    mail_analyzers = [
        "EmailRep_1_0",
        "Abuse_Finder_3_0"
    ]

    for analyzer in mail_analyzers:
        payload = {
            "analyzerId": analyzer,
            "artifactId": mail_observable_id,
            "cortexId": CORTEX_ID
        }

        response = requests.post(job_url, headers=headers, json=payload, verify=False)

        print(f"\n[+] Running analyzer on mail: {analyzer}")
        print("Status:", response.status_code)

        try:
            print(json.dumps(response.json(), indent=2))
        except Exception:
            print(response.text)

print("\n[+] Full automated workflow complete")