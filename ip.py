#!/usr/bin/env python3
"""
originhunt.py — vendor-aware origin IP discovery

Finds real origin hosts behind CDNs. Does NOT treat HTTP 200 as proof:
classifies every candidate by ASN and reverse-DNS tier, then scores on
cert SANs, Host-header-mismatch behaviour and CDN header tells.

  python3 originhunt.py -t example.com
  python3 originhunt.py -t example.com --json out.json --threads 60
  python3 originhunt.py -t example.com --sources crt,spf,brute
  python3 originhunt.py -t example.com --strict     # only >=60 shown

Requires: python3 (stdlib only). No dig, no pip.
"""
import argparse, concurrent.futures as cf, ipaddress, json, os, random, re
import socket, ssl, struct, sys, tempfile, time, urllib.request, urllib.error

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 originhunt/2.1"
TIMEOUT = 6.0
MAX_READ = 8192

# ---------------------------------------------------------------- vendor map
# asn -> (name, edge_only). edge_only=True: vendor terminates TLS at its own
# edge and has NO publicly routable origin tier.
VENDORS = {
    13335: ("Cloudflare", True), 209242: ("Cloudflare", True),
    20940: ("Akamai", True), 16625: ("Akamai", True), 21342: ("Akamai", True),
    54113: ("Fastly", True),
    16509: ("AWS", False), 14618: ("AWS", False),
    8075: ("Azure", False), 396982: ("Google Cloud", False), 15169: ("Google", False),
    19551: ("Imperva", True), 30148: ("Sucuri", True),
    60068: ("CDN77", True), 42159: ("StackPath", True), 200325: ("BunnyCDN", True),
    32934: ("Meta", True), 54115: ("Meta", True), 63293: ("WhatsApp", True), 11917: ("Meta", True),
    9009: ("M247", False), 24940: ("Hetzner", False), 14061: ("DigitalOcean", False),
}
CDN_HEADERS = ("cf-ray", "x-served-by", "x-akamai", "x-cache", "x-fb-debug",
               "x-amz-cf-id", "x-azure-ref", "x-sucuri-id", "x-cdn", "alt-svc")
EDGE_RDNS = re.compile(r"(edge|shv|cdn|star|bb\d|br\d|pr\d|ar\d|ae\d|"
                       r"akamai|fastly|cloudflare|cloudfront|fbcdn|tfbnw|"
                       r"cache|proxy|lb\d)", re.I)
ORIGIN_RDNS = re.compile(r"^(direct|origin|backend|internal|host|srv|server|"
                         r"web\d?|node\d?|app\d?|prod|live|dc\d)", re.I)

SUBS = """direct origin origin-www backend backend-www internal intranet web www www2
www3 www-origin origin1 origin2 srv server host app app-origin api api-origin admin
portal cpanel mail smtp imap ftp vpn gw gateway proxy lb node node1 c1 c2 s1 s2
dc1 dc2 prod production live staging stage dev test old new m mobile static-origin
assets-origin media-origin img-origin cdn-origin edge-origin ns1 ns2""".split()

# ---------------------------------------------------------------- DNS (pure)
def _resolver():
    try:
        for line in open("/etc/resolv.conf"):
            p = line.split()
            if len(p) >= 2 and p[0] == "nameserver":
                return p[1]
    except Exception:
        pass
    return "1.1.1.1"

def _name_at(data, off):
    labels, jumped, ret, guard = [], False, off, 0
    while True:
        if off >= len(data):
            break
        l = data[off]
        if l & 0xC0 == 0xC0:
            if not jumped:
                ret = off + 2
            off = ((l & 0x3F) << 8) | data[off + 1]
            jumped = True
            guard += 1
            if guard > 40:
                break
        elif l == 0:
            off += 1
            break
        else:
            labels.append(data[off + 1:off + 1 + l].decode("latin1"))
            off += 1 + l
    return ".".join(labels), (ret if jumped else off)

def _dns_query(name, qtype, timeout=4.0):
    """Minimal UDP DNS client. qtype: 1=A 5=CNAME 12=PTR 15=MX 16=TXT."""
    srv = _resolver()
    fam = socket.AF_INET6 if ":" in srv else socket.AF_INET
    tid = random.randint(0, 0xFFFF)
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for label in name.rstrip(".").split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + struct.pack(">HH", qtype, 1)
    s = socket.socket(fam, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(q, (srv, 53))
        data, _ = s.recvfrom(4096)
    except Exception:
        return []
    finally:
        s.close()
    try:
        qd, an = struct.unpack(">HH", data[4:8])
        off = 12
        for _ in range(qd):
            _, off = _name_at(data, off)
            off += 4
        out = []
        for _ in range(an):
            _, off = _name_at(data, off)
            rtype, _, _, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            if rtype == qtype:
                if qtype == 16:
                    txt, i = [], 0
                    while i < len(data[off:off + rdlen]):
                        n = data[off + i]
                        txt.append(data[off + i + 1:off + i + 1 + n].decode("latin1"))
                        i += 1 + n
                    out.append("".join(txt))
                elif qtype == 15:
                    out.append(_name_at(data, off + 2)[0])
                elif qtype in (12, 5):
                    out.append(_name_at(data, off)[0])
                elif qtype == 1:
                    out.append(".".join(str(b) for b in data[off:off + rdlen]))
            off += rdlen
        return out
    except Exception:
        return []

def asn_of(ip):
    if ":" in ip:
        nib = ipaddress.IPv6Address(ip).exploded.replace(":", "")
        rev = ".".join(reversed(nib)) + ".origin6.asn.cymru.com"
    else:
        rev = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    for rec in _dns_query(rev, 16):
        try:
            return int(rec.split("|")[0].strip().strip('"'))
        except (ValueError, IndexError):
            pass
    return None

def rdns(ip):
    if ":" in ip:
        nib = ipaddress.IPv6Address(ip).exploded.replace(":", "")
        rev = ".".join(reversed(nib)) + ".ip6.arpa"
    else:
        rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    out = _dns_query(rev, 12)
    return out[0].rstrip(".") if out else ""

def vendor_of(asn):
    return VENDORS.get(asn, (None, False))

def resolve(host):
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
    except Exception:
        return []

# ---------------------------------------------------------------- TLS / cert
def san_match(cert, host):
    san = [v.lower() for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    h = host.lower()
    hit = h in san
    if not hit:
        for s in san:
            if s.startswith("*.") and h.count(".") == s.count(".") and h.endswith(s[1:]):
                hit = True
                break
    return hit, len(san)

def decode_der(der):
    pem = ssl.DER_cert_to_PEM_cert(der)
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
        f.write(pem)
        path = f.name
    try:
        return ssl._ssl._test_decode_cert(path)
    except Exception:
        return {}
    finally:
        try:
            os.unlink(path)
        except Exception:
            pass

# ---------------------------------------------------------------- probing
def probe(ip, host, port=443):
    r = {"ip": ip, "port": port, "open": False, "tls": False, "chain_invalid": False,
         "cert_present": False, "san_match": False, "san_count": 0, "status": None,
         "hdr": {}, "body_ok": False, "mismatch_status": None,
         "mismatch_differs": False, "rotates": False}
    try:
        raw = socket.create_connection((ip, port), timeout=TIMEOUT)
    except Exception:
        return r
    r["open"] = True
    s = None
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED   # CERT_NONE returns {} from getpeercert()
        ctx.set_alpn_protocols(["http/1.1"])
        try:
            s = ctx.wrap_socket(raw, server_hostname=host)
            cert = s.getpeercert()
        except ssl.SSLError:
            try:
                raw.close()
            except Exception:
                pass
            raw = socket.create_connection((ip, port), timeout=TIMEOUT)
            c2 = ssl.create_default_context()
            c2.check_hostname = False
            c2.verify_mode = ssl.CERT_NONE
            s = c2.wrap_socket(raw, server_hostname=host)
            r["chain_invalid"] = True
            cert = decode_der(s.getpeercert(binary_form=True))
        r["tls"] = True
        r["cert_present"] = bool(cert)
        r["san_match"], r["san_count"] = san_match(cert, host)

        def req(h):
            s.sendall(f"GET / HTTP/1.1\r\nHost: {h}\r\nUser-Agent: {UA}\r\n"
                      f"Accept: */*\r\nConnection: close\r\n\r\n".encode())
            buf = b""
            while len(buf) < MAX_READ:
                try:
                    c = s.recv(4096)
                except Exception:
                    break
                if not c:
                    break
                buf += c
            head, _, body = buf.partition(b"\r\n\r\n")
            lines = head.decode("latin1").split("\r\n")
            code, hdrs = None, {}
            m = re.match(r"HTTP/\d(?:\.\d)? (\d{3})", lines[0]) if lines else None
            if m:
                code = int(m.group(1))
            for ln in lines[1:]:
                if ":" in ln:
                    k, v = ln.split(":", 1)
                    hdrs[k.strip().lower()] = v.strip()
            return code, hdrs, body

        code, hdrs, body = req(host)
        r["status"], r["hdr"] = code, hdrs
        label = host.split(".")[0]
        r["body_ok"] = label.encode() in body.lower() or b"<html" in body.lower()

        try:
            mcode, _, mbody = req(f"nope-{random.randint(1000,9999)}.invalid")
            r["mismatch_status"] = mcode
            r["mismatch_differs"] = (mcode != code) or (len(mbody) != len(body))
        except Exception:
            pass

        try:
            _, h2, _ = req(host)
            for k in ("etag", "x-request-id", "x-fb-debug", "x-served-by"):
                if k in hdrs and hdrs[k] != h2.get(k):
                    r["rotates"] = True
        except Exception:
            pass
    except Exception:
        pass
    finally:
        for o in (s, raw):
            try:
                o.close()
            except Exception:
                pass
    return r

# ---------------------------------------------------------------- scoring
def score(c):
    s, why = 0, []
    if c["san_match"]:
        s += 40; why.append("+40 SAN match")
        if c["san_count"] == 1:
            s += 15; why.append("+15 dedicated cert")
        elif c["san_count"] > 3:
            s -= 10; why.append("-10 shared multi-SAN")
    if c["chain_invalid"]:
        s -= 5; why.append("-5 invalid chain")
    if c["mismatch_differs"]:
        s += 20; why.append("+20 Host-mismatch rejects")
    hits = [h for h in CDN_HEADERS if h in c["hdr"]]
    if not hits:
        s += 15; why.append("+15 no CDN headers")
    else:
        d = min(15, 5 * len(hits))
        s -= d; why.append(f"-{d} CDN headers {hits}")
    ptr = c.get("ptr", "")
    if ORIGIN_RDNS.search(ptr):
        s += 10; why.append("+10 origin-ish rDNS")
    if EDGE_RDNS.search(ptr):
        s -= 20; why.append("-20 edge rDNS")
    v, edge_only = vendor_of(c.get("asn"))
    if edge_only:
        s -= 30; why.append(f"-30 {v} edge-only ASN")
    if c["body_ok"]:
        s += 10; why.append("+10 serves target content")
    return s, why

# ---------------------------------------------------------------- collectors
def http_get(url, timeout=TIMEOUT):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read(400_000).decode("utf-8", "ignore")

def from_crtsh(d):
    for attempt in range(4):
        try:
            st, body = http_get(f"https://crt.sh/?q=%25.{d}&output=json")
            if st == 200:
                return {n.strip().lstrip("*.") for row in json.loads(body)
                        for n in row.get("name_value", "").splitlines() if n.strip()}
        except urllib.error.HTTPError as e:
            if e.code in (429, 502, 503):
                time.sleep(3 * (attempt + 1)); continue
        except Exception:
            pass
        time.sleep(2)
    return set()

def from_certspotter(d):
    for attempt in range(3):
        try:
            st, body = http_get("https://api.certspotter.com/v1/issuances"
                                f"?domain={d}&include_subdomains=true&expand=dns_names")
            if st == 200:
                return {n.lstrip("*.") for row in json.loads(body)
                        for n in row.get("dns_names", [])}
        except urllib.error.HTTPError as e:
            if e.code == 429:
                time.sleep(2 * (attempt + 1)); continue
        except Exception:
            pass
    return set()

def from_hackertarget(d):
    try:
        st, body = http_get(f"https://api.hackertarget.com/hostsearch/?q={d}")
        if st == 200 and "error" not in body[:40]:
            return {l.split(",")[0] for l in body.splitlines() if "," in l}
    except Exception:
        pass
    return set()

def from_rapiddns(d):
    try:
        st, body = http_get(f"https://rapiddns.io/subdomain/{d}?full=1")
        if st == 200:
            return set(re.findall(r"<td>([a-z0-9._-]+\." + re.escape(d) + r")</td>", body))
    except Exception:
        pass
    return set()

def from_mail(d):
    out = set()
    for t in _dns_query(d, 15):
        out.add(t.lower().rstrip("."))
    for t in _dns_query(d, 16):
        if "v=spf1" in t.lower():
            out |= {m.lstrip("*.") for m in re.findall(
                r"(?:a:|include:|ip4:|mx:)?([a-z0-9.-]+\." + re.escape(d) + r")", t.lower())}
    return out

def from_brute(d):
    def one(s):
        h = f"{s}.{d}"
        return h if resolve(h) else None
    found = set()
    with cf.ThreadPoolExecutor(max_workers=40) as ex:
        for h in ex.map(one, SUBS):
            if h:
                found.add(h)
    return found

# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-t", "--target", required=True)
    ap.add_argument("--json")
    ap.add_argument("--threads", type=int, default=40)
    ap.add_argument("--sources", default="crt,cs,ht,rd,mail,brute")
    ap.add_argument("--strict", action="store_true", help="hide EDGE block")
    ap.add_argument("--no-color", action="store_true")
    a = ap.parse_args()
    d = a.target.lower().strip(".")
    src = set(a.sources.split(","))

    def C(txt, code=""):
        return txt if a.no_color else f"\033[{code}m{txt}\033[0m"

    print(C(f"[*] target {d}", "36"))
    apex = set(resolve(d))
    if not apex:
        sys.exit(C("[!] target does not resolve", "31"))

    # query FQDN *and* apex: wildcard certs never match the FQDN
    queries = {d} | ({d.split(".", 1)[1]} if d.count(".") > 1 else set())
    hosts = set()
    for name, fn in (("crt", from_crtsh), ("cs", from_certspotter),
                     ("ht", from_hackertarget), ("rd", from_rapiddns),
                     ("mail", from_mail), ("brute", from_brute)):
        if name not in src:
            continue
        got = set()
        for q in queries:
            got |= {h for h in fn(q) if h.endswith(d)}
        print(f"  [src] {name:<6} +{len(got)}")
        hosts |= got

    cand = set(apex)
    for h in hosts:
        cand |= set(resolve(h))
    cand = {ip for ip in cand if ":" in ip or ipaddress.ip_address(ip).is_global}
    print(f"  [*] {len(cand)} unique candidate IP{'s' if len(cand) != 1 else ''} "
          f"from {len(hosts)} hostname{'s' if len(hosts) != 1 else ''}")

    def work(ip):
        c = probe(ip, d)
        c["ptr"] = rdns(ip)
        c["asn"] = asn_of(ip)
        c["vendor"], c["edge_only"] = vendor_of(c["asn"])
        c["score"], c["why"] = score(c)
        return c

    with cf.ThreadPoolExecutor(max_workers=a.threads) as ex:
        results = [r for r in ex.map(work, sorted(cand)) if r["open"]]

    results.sort(key=lambda c: -c["score"])
    verified = [c for c in results if c["score"] >= 60]
    weak = [c for c in results if 20 <= c["score"] < 60]
    edge = [c for c in results if c["score"] < 20]

    def show(title, rows, color):
        print("\n" + C(f"── {title} ({len(rows)})", color))
        for c in rows:
            print(f"  {C(str(c['score']).rjust(3), color)}  {c['ip']:<40} "
                  f"{c['vendor'] or '?':<14} {c['ptr'] or '-'}")
            print(f"       {'; '.join(c['why'])}")

    show("VERIFIED — likely origin", verified, "32")
    show("WEAK — needs manual check", weak, "33")
    if not a.strict:
        show("EDGE / CDN — not origin", edge, "90")

    if not verified:
        tail = " — target may be edge-only (no bypass exists)" if any(
            c["edge_only"] for c in results) else ""
        print(C(f"\n[!] no verified origin{tail}", "31"))

    if a.json:
        with open(a.json, "w") as f:
            json.dump({"target": d, "results": results}, f, indent=2)
        print(f"\n[*] wrote {a.json}")

if __name__ == "__main__":
    main()
