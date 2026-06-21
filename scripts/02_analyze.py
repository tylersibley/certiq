import json
import os
import re
from collections import defaultdict

BATCH1_DIR = "/home/claude/cert_data"
BATCH2_DIR = "/home/claude/cert_data/batch2"
BATCH3_DIR = "/home/claude/cert_data/batch3"
BATCH4_DIR = "/home/claude/cert_data/batch4"

CERT_PATTERNS = {
    "CISSP": r"\bCISSP\b",
    "CISM": r"\bCISM\b",
    "CISA": r"\bCISA\b",
    "Security+": r"\bSecurity\+|\bSecurity Plus\b",
    "CySA+": r"\bCySA\+|\bCySA Plus\b",
    "CRISC": r"\bCRISC\b",
    "CCSP": r"\bCCSP\b",
    "CEH": r"\bCEH\b|\bCertified Ethical Hacker\b",
    "GSEC": r"\bGSEC\b",
    "OSCP": r"\bOSCP\b",
    "GCIH": r"\bGCIH\b",
    "GPEN": r"\bGPEN\b",
    "GWAPT": r"\bGWAPT\b",
    "PenTest+": r"\bPenTest\+|\bPentest Plus\b",
    "CC (ISC2)": r"\bISC2 CC\b|\bISC² CC\b|\bCertified in Cybersecurity\b",
    "SSCP": r"\bSSCP\b",
    "CASP+": r"\bCASP\+|\bCASP Plus\b",
    "AWS Security Specialty": r"\bAWS Certified Security\b|\bAWS Security Specialty\b",
    "AWS Cloud Practitioner": r"\bAWS Certified Cloud Practitioner\b",
    "AWS Solutions Architect": r"\bAWS Certified Solutions Architect\b|\bAWS SAA\b",
    "AZ-500": r"\bAZ-500\b|\bAzure Security Engineer Certif",
    "SC-200": r"\bSC-200\b",
    "SC-300": r"\bSC-300\b",
    "SC-100": r"\bSC-100\b",
    "Google Cloud Security": r"\bGoogle Professional Cloud Security\b|\bGCP Security Engineer\b",
    "PCNSE": r"\bPCNSE\b",
    "Okta Certified": r"\bOkta Certified\b|\bOkta Professional\b|\bOkta Administrator Certif",
    "SailPoint Certified": r"\bSailPoint Certified\b|\bIdentityNow Certif",
    "CIPP": r"\bCIPP\b",
    "CDPSE": r"\bCDPSE\b",
    "ISO 27001 Lead": r"\bISO 27001 Lead\b|\bISO/IEC 27001 Lead\b",
    "CGEIT": r"\bCGEIT\b",
    "CHFI": r"\bCHFI\b",
    "CTIA": r"\bCTIA\b",
    "ITIL": r"\bITIL\b",
    "PMP": r"\bPMP\b",
    "CCISO": r"\bCCISO\b|\bCertified CISO\b",
    "Network+": r"\bNetwork\+\b",
    "CCNA": r"\bCCNA\b",
}

CATEGORY_QUERY_MAP_B1 = {
    "information security engineer": "general",
    "identity access management engineer": "iam",
    "GRC analyst": "grc",
    "cloud security engineer": "cloud",
    "penetration tester": "pentest",
    "security operations analyst": "general",
    "security manager": "mgmt",
    "IAM specialist": "iam",
    "compliance analyst cybersecurity": "grc",
    "SOC analyst": "entry",
    "security architect": "mgmt",
    "incident response analyst": "entry",
    "risk analyst cybersecurity": "grc",
    "application security engineer": "general",
    "cybersecurity analyst": "entry",
}

cert_mentions = defaultdict(int)
cert_by_category = defaultdict(lambda: defaultdict(int))
cert_salaries = defaultdict(list)
category_posting_counts = defaultdict(int)
total_postings = 0
postings_with_salary = 0
seen_job_ids = set()

def process_posting(posting, category):
    global total_postings, postings_with_salary
    job_id = posting.get("job_id")
    if job_id and job_id in seen_job_ids:
        return  # dedupe across overlapping queries
    if job_id:
        seen_job_ids.add(job_id)

    total_postings += 1
    category_posting_counts[category] += 1
    title = posting.get("job_title", "") or ""
    desc = posting.get("job_description", "") or ""
    full_text = f"{title} {desc}"

    min_sal = posting.get("job_min_salary")
    max_sal = posting.get("job_max_salary")
    avg_sal = None
    if min_sal and max_sal:
        avg_sal = (min_sal + max_sal) / 2
        postings_with_salary += 1

    found_certs = set()
    for cert, pattern in CERT_PATTERNS.items():
        if re.search(pattern, full_text, re.IGNORECASE):
            found_certs.add(cert)

    for cert in found_certs:
        cert_mentions[cert] += 1
        cert_by_category[category][cert] += 1
        if avg_sal:
            cert_salaries[cert].append(avg_sal)

# Batch 1 (flat files, query name -> category via map)
for fname in os.listdir(BATCH1_DIR):
    if not fname.endswith(".json"):
        continue
    query_name = fname.replace(".json", "").replace("_", " ")
    if query_name not in CATEGORY_QUERY_MAP_B1:
        continue
    category = CATEGORY_QUERY_MAP_B1[query_name]
    with open(os.path.join(BATCH1_DIR, fname)) as f:
        try:
            data = json.load(f)
        except:
            continue
    for posting in data.get("data", []):
        process_posting(posting, category)

# Batch 2 (wrapped files with category embedded)
for fname in os.listdir(BATCH2_DIR):
    if not fname.endswith(".json"):
        continue
    with open(os.path.join(BATCH2_DIR, fname)) as f:
        try:
            wrapped = json.load(f)
        except:
            continue
    category = wrapped.get("category", "general")
    response = wrapped.get("response", {})
    for posting in response.get("data", []):
        process_posting(posting, category)

# Batch 3 (wrapped files with category embedded, targeted reinforcement queries)
for fname in os.listdir(BATCH3_DIR):
    if not fname.endswith(".json"):
        continue
    with open(os.path.join(BATCH3_DIR, fname)) as f:
        try:
            wrapped = json.load(f)
        except:
            continue
    category = wrapped.get("category", "general")
    response = wrapped.get("response", {})
    for posting in response.get("data", []):
        process_posting(posting, category)

# Batch 4 (final targeted reinforcement)
for fname in os.listdir(BATCH4_DIR):
    if not fname.endswith(".json"):
        continue
    with open(os.path.join(BATCH4_DIR, fname)) as f:
        try:
            wrapped = json.load(f)
        except:
            continue
    category = wrapped.get("category", "general")
    response = wrapped.get("response", {})
    for posting in response.get("data", []):
        process_posting(posting, category)

print(f"=== TOTAL UNIQUE POSTINGS: {total_postings} ===")
print(f"Postings with salary data: {postings_with_salary} ({postings_with_salary/total_postings*100:.0f}%)")
print(f"\n--- POSTINGS PER CATEGORY (sample size / confidence) ---")
for cat, n in sorted(category_posting_counts.items(), key=lambda x: -x[1]):
    confidence = "HIGH" if n >= 40 else "MEDIUM" if n >= 20 else "LOW"
    print(f"{cat}: {n} postings [{confidence} confidence]")

print(f"\n--- OVERALL CERT RANKING ---")
for cert, count in sorted(cert_mentions.items(), key=lambda x: -x[1]):
    sal_list = cert_salaries.get(cert, [])
    sal_str = f"${sum(sal_list)/len(sal_list):,.0f} (n={len(sal_list)})" if sal_list else "no salary data"
    print(f"{cert}: {count} mentions | {sal_str}")

print(f"\n--- BY CATEGORY (top 10 each) ---")
for cat, certs in sorted(cert_by_category.items()):
    n_postings = category_posting_counts[cat]
    print(f"\n{cat.upper()} (n={n_postings} postings):")
    for cert, count in sorted(certs.items(), key=lambda x: -x[1])[:10]:
        print(f"  {cert}: {count}")

output = {
    "total_unique_postings": total_postings,
    "postings_with_salary": postings_with_salary,
    "category_posting_counts": dict(category_posting_counts),
    "cert_mentions": dict(cert_mentions),
    "cert_by_category": {k: dict(v) for k, v in cert_by_category.items()},
    "cert_salaries": {k: v for k, v in cert_salaries.items()},
}
with open("/home/claude/cert_data/final_analysis_v3.json", "w") as f:
    json.dump(output, f, indent=2)
print("\nSaved final_analysis_v3.json")
