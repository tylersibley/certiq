# CertIQ — Cybersecurity Certification Report

A data-driven report ranking cybersecurity certifications by real employer demand and salary, broken out across seven job domains (IAM, Cloud Security, Pentest, GRC, Management, Entry-Level, and Overall).

**[Live report →](https://tylersibley.dev/certiq)** *(update this link once deployed)*

## What this is

914 unique, deduplicated cybersecurity job postings pulled live from Indeed, LinkedIn, and ZipRecruiter via the [JSearch API](https://rapidapi.com/letscrape-6bRBa3QguO5/api/jsearch), scanned for mentions of 32 cybersecurity certifications, broken out by domain.

This is a **static snapshot**, not a live feed. Data was pulled in June 2026 and should be re-pulled periodically to stay current — see `scripts/` for the pull and analysis scripts used to generate it.

## What this isn't

A comprehensive labor market census. Lightcast and the Bureau of Labor Statistics draw on millions of postings; this draws on under a thousand. It's enough to establish *relative* ranking within a category — not to treat small gaps in mention count as statistically significant. Full caveats are in the report's methodology section.

## Structure

```
certiq-repo/
├── index.html              # the report itself, static HTML/CSS/JS, no build step
├── data/
│   └── cert_demand_data.json   # raw aggregated analysis output (mentions, salaries, sample sizes per category)
└── README.md
```

## Methodology summary

- **Source:** JSearch API (Indeed / LinkedIn / ZipRecruiter aggregation), free tier
- **Queries:** 47 targeted role-based searches across 7 domains
- **Cert detection:** regex pattern matching against job titles + descriptions for 32 cybersecurity certifications
- **Salary:** calculated only from postings that disclosed a pay range (32% of postings); figures from fewer than 3 disclosed postings are flagged directional
- **Dedup:** postings deduplicated by job ID across overlapping search queries

## Running it locally

This is a static single HTML file — no build step, no dependencies. Open `index.html` in any browser, or serve it:

```bash
python3 -m http.server 8000
```

## License / use

Data and methodology are open for reference and citation. If you reuse the ranking or figures, a link back is appreciated.

---

Built by [Tyler Sibley](https://tylersibley.dev) · Okta Certified Professional · AWS Certified
