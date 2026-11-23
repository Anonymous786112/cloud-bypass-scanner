# 🔍 Origin-Seeker (CDN & Cloudflare Origin IP Finder)

**Origin-Seeker** is an advanced Python-based reconnaissance and heuristic scoring tool designed to uncover true origin IPs of domains behind CDNs, reverse proxies, or cloud firewalls, while intelligently filtering out public edge nodes and CDN caches.

---

## 🚀 Features

- **Multi-Angle Reconnaissance:**
  - Deep DNS Record Analysis (A, AAAA, MX, TXT/SPF, SOA, NS).
  - Certificate Transparency Logs (`crt.sh`) integration.
  - OSINT & Subdomain mapping (HackerTarget API integration).
  - Common bypass subdomain brute-forcing.
- **Smart Heuristic Scoring Engine:**
  - Evaluates candidate IPs using TLS Subject Alternative Name (SAN) matching.
  - Detects Host-header mismatch rejections.
  - Identifies CDN/Edge headers (`x-fb-debug`, `alt-svc`, etc.).
  - Analyzes Reverse DNS (`rDNS`) patterns to separate true origins from CDN nodes.
- **Flexible Output:** Supports CLI formatting and JSON export (`--json`) for automated workflows.


