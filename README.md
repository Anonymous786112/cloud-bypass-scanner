# 🔍 Origin-Seeker (Vendor-Aware Origin IP Discovery)

**Origin-Seeker** is an advanced Python-based reconnaissance and heuristic scoring tool designed to uncover true origin IPs behind CDNs and reverse proxies. It does not blindly trust HTTP 200 responses; instead, it classifies every candidate by ASN and reverse-DNS tier, scoring them based on Certificate SANs, Host-header mismatch behavior, and CDN header indicators.

---

## 🚀 Features

- **Zero-Dependency Core:** Pure Python standard library design (No external packages like `dig` or `pip` dependencies required for core execution).
- **Multi-Source Collection:**
  - Certificate Transparency logs (`crt.sh`, CertSpotter)
  - OSINT APIs (HackerTarget, RapidDNS)
  - Mail Infrastructure & SPF records analysis
  - Built-in multi-threaded subdomain brute-forcing
- **Smart Heuristic Scoring Engine:**
  - Evaluates candidate IPs using TLS Subject Alternative Name (SAN) matching and certificate type.
  - Detects Host-header mismatch behavior (`+20` for rejections).
  - Flags and penalizes CDN/Edge headers (`x-fb-debug`, `alt-svc`, etc.).
  - Inspects Reverse DNS (`rDNS`) patterns to separate origin-like hosts from edge nodes.
- **Flexible CLI Options:** Supports strict filtering, custom thread counts, colorized output, and JSON export.

---

## 📦 Installation

Clone the repository to your local machine:

```bash
git clone https://github.com/Anonymous786112/cloud-bypass-scanner.git
cd cloud-bypass-scanner
```

---

## ⚙️ Usage

Run a standard scan on a target domain:

```bash
python3 ip.py -t example.com
```

### Advanced Options:

- **Export results to JSON with custom threads:**
  ```bash
  python3 ip.py -t example.com --json out.json --threads 60
  ```
- **Query specific discovery sources only:**
  ```bash
  python3 ip.py -t example.com --sources crt,spf,brute
  ```
- **Run in strict mode (hide EDGE blocks):**
  ```bash
  python3 ip.py -t example.com --strict
  ```
- **Disable terminal color output:**
  ```bash
  python3 ip.py -t example.com --no-color
  ```

---

## 📊 Heuristic Scoring Breakdown

The script scores candidate IPs to determine their likelihood of being a true backend origin server:
- **`+40`** : TLS Certificate SAN match with target domain.
- **`+15`** : Dedicated single-SAN certificate.
- **`-10`** : Shared multi-SAN certificate.
- **`-5`**  : Invalid certificate chain.
- **`+20`** : Host-header mismatch response differs.
- **`+15`** : No CDN headers detected.
- **`-[x]`** : Penalty points applied for presence of CDN headers (e.g., `x-fb-debug`, `alt-svc`).
- **`+10`** : Origin-like rDNS naming convention.
- **`-20`** : Edge rDNS naming convention detected (`edge`, `shv`, `cdn`, etc.).
- **`-30`** : Edge-only vendor ASN mapping.
- **`+10`** : Successfully serves target content body.

---

## 🛠️ Requirements

- Python 3.x (Standard Library only)

---

## ⚠️ Disclaimer

This tool is created for educational purposes, authorized security auditing, and penetration testing only. The author is not responsible for any misuse or illegal activities conducted using this software.
