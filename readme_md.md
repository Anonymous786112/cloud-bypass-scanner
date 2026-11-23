# 🔍 OriginHunt (`cloud-bypass-scanner`)

**OriginHunt** is a zero-dependency, vendor-aware Python reconnaissance tool designed to identify real origin hosts behind CDNs and reverse proxies. Instead of blindly treating an `HTTP 200` response as proof of an origin IP, it classifies every candidate by ASN and reverse-DNS tier, then applies a heuristic scoring model based on TLS certificate SANs, Host-header mismatch behavior, and CDN edge headers.

---

## ✨ Key Features

- **Zero External Dependencies:** Built entirely with the Python 3 standard library (no `pip`, `dnspython`, or `dig` required). Includes a custom raw UDP DNS client and TLS certificate parser.
- **Vendor-Aware ASN Classification:** Automatically queries Team Cymru ASN DNS lookups to map candidate IPs against major edge-only CDN vendors (Cloudflare, Akamai, Fastly, Imperva, Meta, etc.) vs. cloud/VPS hosting providers (AWS, DigitalOcean, Hetzner, GCP).
- **Multi-Source Enumeration:**
  - Certificate Transparency Logs (`crt.sh` & `CertSpotter`)
  - OSINT Subdomain Mapping (`HackerTarget` & `RapidDNS`)
  - Mail & SPF DNS Record Extraction (`MX` & `TXT` records)
  - Multi-threaded Subdomain Brute-forcing
- **Heuristic Scoring Engine:**
  - Evaluates TLS Subject Alternative Name (SAN) matches and dedicated vs. shared certificates.
  - Tests server behavior using randomized invalid `Host` headers.
  - Detects CDN/Edge response headers (`cf-ray`, `x-fb-debug`, `x-served-by`, `alt-svc`, etc.).
  - Analyzes Reverse DNS (`PTR`) patterns (`edge`/`shv`/`cdn` vs. `origin`/`direct`/`backend`).

---

## 🚀 Installation

Since this tool uses only the Python standard library, no package installation is needed:

```bash
git clone https://github.com/Anonymous786112/cloud-bypass-scanner.git
cd cloud-bypass-scanner
chmod +x ip.py
```

*(Requires Python 3.7+)*

---

## ⚙️ Usage

Run a full reconnaissance scan against a target domain:

```bash
python3 ip.py -t example.com
```

### Command-Line Options

| Flag | Description |
| :--- | :--- |
| `-t`, `--target` | Target domain name (Required) |
| `--sources` | Comma-separated list of sources (`crt,cs,ht,rd,mail,brute`) |
| `--threads` | Number of concurrent probing threads (Default: `40`) |
| `--strict` | Hide `EDGE / CDN` results and show only higher-scoring candidates |
| `--json` | Export full scan results and heuristic breakdown to a JSON file |
| `--no-color` | Disable ANSI terminal colors |

### Examples

```bash
# Run using only quiet/passive DNS and brute-force sources
python3 ip.py -t example.com --sources brute,mail

# Increase threads and save output to JSON
python3 ip.py -t example.com --threads 60 --json results.json

# Strict mode (hide known CDN/edge nodes)
python3 ip.py -t example.com --strict
```

---

## 📊 Heuristic Scoring System

Candidates are scored and categorized into three tiers (**Verified** `>= 60`, **Weak** `20–59`, and **Edge/CDN** `< 20`):

- **`+40`** : TLS Certificate SAN matches the target domain
- **`+15`** : Dedicated single-domain TLS certificate (`SAN count == 1`)
- **`+20`** : Server rejects or alters response on invalid `Host` header mismatch
- **`+15`** : No known CDN headers detected in HTTP response
- **`+10`** : Origin-like Reverse DNS pattern (`origin`, `direct`, `backend`, `srv`, etc.)
- **`+10`** : Response body serves expected target content
- **`-10`** : Shared multi-SAN certificate (`SAN count > 3`)
- **`-20`** : Edge/CDN Reverse DNS pattern (`edge`, `shv`, `cdn`, `fbcdn`, etc.)
- **`-30`** : IP belongs to an edge-only CDN ASN (e.g., Cloudflare, Akamai, Fastly)

---

## ⚠️ Disclaimer

This tool is intended strictly for educational purposes, authorized security assessments, and defensive infrastructure auditing. Always ensure you have explicit permission before scanning any target domain or network.