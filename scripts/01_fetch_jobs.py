import urllib.request
import urllib.parse
import json
import time
import os

import os
API_KEY = os.environ.get("JSEARCH_API_KEY")
if not API_KEY:
    raise SystemExit("Set the JSEARCH_API_KEY environment variable before running this script.")
HOST = "jsearch.p.rapidapi.com"

QUERIES = [
    "cybersecurity analyst",
    "information security engineer",
    "identity access management engineer",
    "GRC analyst",
    "cloud security engineer",
    "penetration tester",
    "security operations analyst",
    "security manager",
    "IAM specialist",
    "compliance analyst cybersecurity",
    "SOC analyst",
    "security architect",
    "incident response analyst",
    "risk analyst cybersecurity",
    "application security engineer",
]

OUT_DIR = "/home/claude/cert_data"
os.makedirs(OUT_DIR, exist_ok=True)

def fetch(query):
    encoded = urllib.parse.quote(query)
    url = f"https://{HOST}/search?query={encoded}&num_pages=1"
    req = urllib.request.Request(url)
    req.add_header("X-RapidAPI-Key", API_KEY)
    req.add_header("X-RapidAPI-Host", HOST)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = resp.read()
            return json.loads(data)
    except Exception as e:
        return {"error": str(e)}

results = {}
for q in QUERIES:
    print(f"Fetching: {q}")
    data = fetch(q)
    fname = q.replace(" ", "_") + ".json"
    path = os.path.join(OUT_DIR, fname)
    with open(path, "w") as f:
        json.dump(data, f)
    n = len(data.get("data", [])) if isinstance(data, dict) else 0
    status = data.get("status", data.get("error", "unknown")) if isinstance(data, dict) else "unknown"
    print(f"  -> {n} results, status: {status}")
    results[q] = n
    time.sleep(1.2)

print("\n--- SUMMARY ---")
for q, n in results.items():
    print(f"{q}: {n} postings")
print(f"\nTotal postings pulled: {sum(results.values())}")
