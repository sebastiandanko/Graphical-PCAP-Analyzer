"""Detection engine.

Two jobs:

1. *Scan detection* -- decide whether the capture contains reconnaissance
   (port scans, sweeps, ARP scans, brute force, zone transfers) and say so in
   plain language.
2. *CTF pattern hunting* -- the things that actually matter when a pcap is a
   challenge: flags (plain, base64, hex, rot13, single-byte XOR), cleartext
   credentials, DNS/ICMP tunnelling, transferred files, web attacks, keys.
"""

from __future__ import annotations

import base64
import binascii
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    detail: str = ""
    evidence: str = ""
    packets: list = field(default_factory=list)
    stream_id: int = -1

    @property
    def rank(self):
        return SEV_RANK.get(self.severity, 9)


# ---------------------------------------------------------------------------
# regexes
# ---------------------------------------------------------------------------

KNOWN_FLAG_RE = re.compile(
    rb"(?i)\b(flag|ctf|key|pico ?ctf|picoctf|htb|thm|tryhackme|hsctf|utflag|actf|"
    rb"nactf|bctf|csictf|sun|inctf|uiuctf|dctf|vulnhub|pwn|crypto)\{[^}\r\n]{1,160}\}")
GENERIC_FLAG_RE = re.compile(rb"\b[A-Za-z][A-Za-z0-9_]{1,15}\{[!-~]{4,160}\}")
B64_RE = re.compile(rb"[A-Za-z0-9+/]{20,}={0,2}")
HEX_RE = re.compile(rb"(?:[0-9a-fA-F]{2}){12,}")
PEM_RE = re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----")
AWS_RE = re.compile(rb"AKIA[0-9A-Z]{16}")
JWT_RE = re.compile(rb"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")

SQLI_RE = re.compile(
    rb"(?i)(union[\s/*]+select|or\s+1\s*=\s*1|'\s*or\s*'1'\s*=\s*'1|sleep\(\d|"
    rb"benchmark\(|information_schema|xp_cmdshell|/\*!\d+)")
TRAVERSAL_RE = re.compile(rb"(?i)(\.\./\.\./|\.\.%2f|%2e%2e/|/etc/passwd|"
                          rb"c:\\windows\\win\.ini|file=/|php://filter)")
CMDI_RE = re.compile(rb"(?i)(;\s*(cat|ls|id|whoami|uname)\b|\|\s*(nc|bash|sh)\b|"
                     rb"%3b(cat|ls|id)|`id`|\$\(id\)|nc\s+-e|bash\s+-i\s*>&|"
                     rb"/dev/tcp/|powershell\s+-e(nc)?\b|certutil\s+-urlcache)")
XSS_RE = re.compile(rb"(?i)(<script[\s>]|onerror\s*=|javascript:alert|<img[^>]+onerror)")
WEBSHELL_RE = re.compile(rb"(?i)(c99shell|r57shell|b374k|wso\d|eval\(\$_(post|get|request)|"
                         rb"system\(\$_|passthru\(|shell_exec\(|cmd\.jsp|antsword)")
BAD_UA_RE = re.compile(rb"(?i)(sqlmap|nikto|nmap( scripting)?|masscan|dirbuster|gobuster|"
                       rb"wpscan|hydra|metasploit|acunetix|nessus|zgrab|curl/|wget/|"
                       rb"python-requests|go-http-client|havij)")

CRED_PATTERNS = [
    (re.compile(rb"(?im)^USER\s+(.+)$"), "FTP/POP3 username", "USER"),
    (re.compile(rb"(?im)^PASS\s+(.+)$"), "FTP/POP3 password", "PASS"),
    (re.compile(rb"(?im)^LOGIN\s+(.+)$"), "IMAP login", "LOGIN"),
    (re.compile(rb"(?im)^AUTH\s+(.+)$"), "SMTP/Redis auth", "AUTH"),
]
HTTP_BASIC_RE = re.compile(rb"(?i)Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)")
HTTP_BEARER_RE = re.compile(rb"(?i)Authorization:\s*Bearer\s+([A-Za-z0-9._\-]+)")
COOKIE_RE = re.compile(rb"(?i)^Cookie:\s*(.+)$", re.M)
FORM_CRED_RE = re.compile(
    rb"(?i)(^|[&?])(user(name)?|login|email|pass(word|wd)?|pwd|token|api[_-]?key)=([^&\s\"']{1,80})")

PLAINTEXT_PROTOS = {"FTP": 21, "TELNET": 23, "HTTP": 80, "SMTP": 25,
                    "POP3": 110, "IMAP": 143, "SNMP": 161, "TFTP": 69,
                    "REDIS": 6379, "MYSQL": 3306, "IRC": 6667, "SYSLOG": 514}

SUSPICIOUS_PORTS = {4444: "Metasploit default handler", 4443: "common reverse shell",
                    1337: "leet / backdoor", 31337: "Back Orifice / leet",
                    9001: "Tor / common shell", 8081: "alt HTTP",
                    5555: "ADB / backdoor", 6666: "IRC bot / backdoor",
                    12345: "NetBus", 54321: "backdoor", 2323: "Telnet backdoor"}

XOR_TABLES = {}


def _xor_table(key):
    tbl = XOR_TABLES.get(key)
    if tbl is None:
        tbl = bytes(b ^ key for b in range(256))
        XOR_TABLES[key] = tbl
    return tbl


def entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def printable_ratio(b):
    if not b:
        return 0.0
    return sum(1 for c in b if 32 <= c < 127 or c in (9, 10, 13)) / len(b)


def _short(b, n=140):
    if isinstance(b, bytes):
        s = b.decode("utf-8", "replace")
    else:
        s = str(b)
    s = "".join(ch if ch.isprintable() or ch == " " else "." for ch in s)
    return s[:n] + ("…" if len(s) > n else "")


# ---------------------------------------------------------------------------
# main entry point
# ---------------------------------------------------------------------------

def analyze(packets, conversations, carved, meta):
    findings = []
    findings += detect_scans(packets, conversations)
    findings += detect_bruteforce(packets, conversations)
    findings += detect_flags(packets, conversations)
    findings += detect_credentials(packets, conversations)
    findings += detect_dns_tunnel(packets)
    findings += detect_icmp_tunnel(packets)
    findings += detect_web_attacks(packets, conversations)
    findings += detect_secrets(conversations)
    findings += detect_files(carved)
    findings += detect_shells(packets, conversations)
    findings += detect_beaconing(conversations, packets)
    findings += detect_plaintext(packets, conversations)
    findings += detect_oddities(packets, conversations, meta)
    findings.sort(key=lambda f: (f.rank, f.category))
    return findings


# ---------------------------------------------------------------------------
# 1. scans / recon
# ---------------------------------------------------------------------------

def detect_scans(packets, conversations):
    out = []
    syn_targets = defaultdict(set)       # src -> {(dst, dport)}
    syn_pkts = defaultdict(list)
    flagcount = defaultdict(Counter)     # (src,dst) -> flag combos
    weird_pkts = defaultdict(list)
    udp_targets = defaultdict(set)
    udp_pkts = defaultdict(list)
    arp_targets = defaultdict(set)
    arp_pkts = defaultdict(list)
    icmp_targets = defaultdict(set)
    icmp_pkts = defaultdict(list)
    synack = defaultdict(set)            # (scanner,target) -> open ports
    rst = defaultdict(int)
    icmp_unreach = defaultdict(int)
    ttl_low = defaultdict(set)

    for p in packets:
        if p.transport == "TCP":
            f = p.tcp_flags & 0x3F
            if f == 0x02:                                   # SYN only
                syn_targets[p.src].add((p.dst, p.dport))
                syn_pkts[p.src].append(p.number)
                flagcount[(p.src, p.dst)]["SYN"] += 1
            elif f == 0x12:                                 # SYN+ACK
                synack[(p.dst, p.src)].add(p.sport)
            elif f in (0x00, 0x01, 0x29, 0x28, 0x03, 0x06, 0x21):
                name = {0x00: "NULL", 0x01: "FIN", 0x29: "XMAS", 0x28: "XMAS",
                        0x03: "SYN+FIN", 0x06: "SYN+RST", 0x21: "FIN+URG"}.get(f, "odd")
                flagcount[(p.src, p.dst)][name] += 1
                weird_pkts[(p.src, p.dst, name)].append(p.number)
                syn_targets[p.src].add((p.dst, p.dport))
            elif f & 0x04:
                rst[(p.dst, p.src)] += 1
            elif f == 0x10 and not p.payload:
                flagcount[(p.src, p.dst)]["ACK"] += 1
            if 0 < p.ttl <= 5:
                ttl_low[p.src].add(p.dst)
        elif p.transport == "UDP" and p.proto not in ("DNS", "MDNS", "DHCP", "NTP"):
            udp_targets[p.src].add((p.dst, p.dport))
            udp_pkts[p.src].append(p.number)
        elif p.proto == "ARP" and "Who has" in p.info:
            arp_targets[p.src].add(p.dst)
            arp_pkts[p.src].append(p.number)
        elif p.proto == "ICMP":
            if "Echo Request" in p.info:
                icmp_targets[p.src].add(p.dst)
                icmp_pkts[p.src].append(p.number)
            elif "Unreachable" in p.info:
                icmp_unreach[p.dst] += 1

    # --- vertical (port) scans and horizontal sweeps -----------------------
    for src, targets in syn_targets.items():
        by_host = defaultdict(set)
        for dst, port in targets:
            by_host[dst].add(port)
        for dst, ports in by_host.items():
            if len(ports) < 12:
                continue
            technique, conf = _scan_technique(flagcount.get((src, dst), Counter()))
            open_ports = sorted(synack.get((src, dst), ()))
            closed = rst.get((src, dst), 0)
            pkt_nums = syn_pkts.get(src, [])[:400]
            span = _timespan(packets, pkt_nums)
            detail = [
                "Host %s probed %d distinct TCP ports on %s." % (src, len(ports), dst),
                "Technique: %s%s." % (technique, conf),
                "Ports touched: %s" % _port_list(sorted(ports)),
                "Responses: %d RST (closed), %d SYN/ACK (open)." % (closed, len(open_ports)),
            ]
            if span:
                detail.append("Elapsed: %s  (%.0f probes/second)" % (span[0], span[1]))
            if open_ports:
                detail.append("OPEN PORTS FOUND: %s" % _port_list(open_ports))
            out.append(Finding(
                "critical" if len(ports) > 100 else "high",
                "Port scan",
                "TCP port scan: %s → %s  (%d ports)" % (src, dst, len(ports)),
                "\n".join(detail),
                "%s scanned %d ports; %d answered open" % (src, len(ports), len(open_ports)),
                pkt_nums))

        hosts = {dst for dst, _ in targets}
        if len(hosts) >= 8:
            per_port = defaultdict(set)
            for dst, port in targets:
                per_port[port].add(dst)
            hot = sorted(per_port.items(), key=lambda kv: -len(kv[1]))[:5]
            if hot and len(hot[0][1]) >= 8:
                ports_desc = ", ".join("%d (%d hosts)" % (p, len(h)) for p, h in hot)
                out.append(Finding(
                    "high", "Network sweep",
                    "Horizontal sweep: %s → %d hosts" % (src, len(hosts)),
                    "Host %s probed the same port(s) across %d different addresses — "
                    "a service-discovery sweep looking for one exposed service.\n"
                    "Top ports: %s\nHosts: %s" % (
                        src, len(hosts), ports_desc, _host_list(sorted(hosts))),
                    "%s swept %d hosts" % (src, len(hosts)),
                    syn_pkts.get(src, [])[:400]))

    # --- stealth flag scans -------------------------------------------------
    for (src, dst, name), nums in weird_pkts.items():
        if len(nums) >= 6:
            out.append(Finding(
                "high", "Port scan",
                "%s scan: %s → %s" % (name, src, dst),
                "%d TCP packets with an illegal/unusual flag combination (%s) were sent.\n"
                "%s scans are stealth techniques used to map firewall behaviour: closed ports "
                "answer with RST, open ports stay silent." % (len(nums), name, name),
                "%d %s packets" % (len(nums), name), nums[:300]))

    # --- UDP scan -----------------------------------------------------------
    for src, targets in udp_targets.items():
        by_host = defaultdict(set)
        for dst, port in targets:
            by_host[dst].add(port)
        for dst, ports in by_host.items():
            if len(ports) >= 15:
                out.append(Finding(
                    "high", "Port scan",
                    "UDP port scan: %s → %s  (%d ports)" % (src, dst, len(ports)),
                    "Host %s sent UDP datagrams to %d distinct ports on %s.\n"
                    "%d ICMP port-unreachable replies came back (closed ports).\n"
                    "Ports: %s" % (src, len(ports), dst, icmp_unreach.get(src, 0),
                                   _port_list(sorted(ports))),
                    "%d UDP ports probed" % len(ports), udp_pkts.get(src, [])[:300]))

    # --- ARP scan -----------------------------------------------------------
    for src, targets in arp_targets.items():
        if len(targets) >= 10:
            out.append(Finding(
                "high", "Network sweep",
                "ARP scan: %s → %d addresses" % (src, len(targets)),
                "Host %s broadcast ARP requests for %d different IP addresses on the local "
                "segment. This is layer-2 host discovery (arp-scan, nmap -PR, netdiscover).\n"
                "Targets: %s" % (src, len(targets), _host_list(sorted(targets))),
                "%d ARP requests" % len(arp_pkts.get(src, [])), arp_pkts.get(src, [])[:300]))

    # --- ICMP sweep ---------------------------------------------------------
    for src, targets in icmp_targets.items():
        if len(targets) >= 8:
            out.append(Finding(
                "high", "Network sweep",
                "ICMP ping sweep: %s → %d hosts" % (src, len(targets)),
                "Host %s sent ICMP echo requests to %d distinct addresses — classic host "
                "discovery before a port scan.\nTargets: %s" % (
                    src, len(targets), _host_list(sorted(targets))),
                "%d echo requests" % len(icmp_pkts.get(src, [])), icmp_pkts.get(src, [])[:300]))

    # --- traceroute ---------------------------------------------------------
    for src, dsts in ttl_low.items():
        if len(dsts) >= 3:
            out.append(Finding(
                "low", "Recon",
                "Traceroute activity from %s" % src,
                "Packets with very low TTL values (≤5) toward %d destinations — path "
                "discovery / traceroute." % len(dsts),
                "low-TTL probes", []))

    # --- DNS zone transfer --------------------------------------------------
    axfr = [p.number for p in packets if p.proto == "DNS" and "AXFR" in p.info]
    if axfr:
        out.append(Finding(
            "high", "Recon", "DNS zone transfer attempt (AXFR)",
            "An AXFR query was issued. A successful zone transfer dumps every record in a "
            "domain — a classic first step in enumeration and a very common CTF gift.",
            "%d AXFR packet(s)" % len(axfr), axfr))
    return out


def _scan_technique(flags):
    syn, ack = flags.get("SYN", 0), flags.get("ACK", 0)
    if flags.get("NULL") or flags.get("FIN") or flags.get("XMAS"):
        return "stealth flag scan (NULL/FIN/XMAS)", " — evades naive logging"
    if syn and ack > syn * 0.6:
        return "TCP connect() scan", " — full handshakes completed (nmap -sT)"
    if syn:
        return "TCP SYN / half-open scan", " — handshake never completed (nmap -sS)"
    return "TCP probing", ""


def _timespan(packets, numbers):
    if len(numbers) < 2:
        return None
    idx = {n - 1 for n in numbers}
    ts = [p.ts for p in packets if p.index in idx]
    if len(ts) < 2:
        return None
    span = max(ts) - min(ts)
    if span <= 0:
        return ("< 1 ms", float(len(ts)))
    return (_dur(span), len(ts) / span)


def _dur(s):
    if s < 1:
        return "%.0f ms" % (s * 1000)
    if s < 90:
        return "%.2f s" % s
    return "%.1f min" % (s / 60)


def _port_list(ports, n=24):
    shown = ", ".join(str(p) for p in ports[:n])
    return shown + (" … (+%d more)" % (len(ports) - n) if len(ports) > n else "")


def _host_list(hosts, n=12):
    shown = ", ".join(hosts[:n])
    return shown + (" … (+%d more)" % (len(hosts) - n) if len(hosts) > n else "")


# ---------------------------------------------------------------------------
# 2. brute force
# ---------------------------------------------------------------------------

def detect_bruteforce(packets, conversations):
    out = []
    attempts = defaultdict(list)          # (src,dst,service) -> packet numbers
    fails = defaultdict(int)
    for p in packets:
        pay = p.payload
        if not pay or len(pay) > 4096:
            continue
        svc = p.proto
        if svc == "FTP" and re.match(rb"(?i)^PASS ", pay):
            attempts[(p.src, p.dst, "FTP")].append(p.number)
        elif svc == "FTP" and pay.startswith(b"530"):
            fails[(p.dst, p.src, "FTP")] += 1
        elif svc in ("POP3", "IMAP") and re.match(rb"(?i)^(PASS |LOGIN )", pay):
            attempts[(p.src, p.dst, svc)].append(p.number)
        elif svc == "HTTP" and b"Authorization: Basic" in pay:
            attempts[(p.src, p.dst, "HTTP Basic")].append(p.number)
        elif svc == "HTTP" and pay.startswith(b"HTTP/1.") and b" 401 " in pay[:20]:
            fails[(p.dst, p.src, "HTTP Basic")] += 1
        elif svc == "SMTP" and re.match(rb"(?i)^(AUTH LOGIN|AUTH PLAIN)", pay):
            attempts[(p.src, p.dst, "SMTP")].append(p.number)

    ssh_conns = defaultdict(list)
    for c in conversations:
        if c.proto == "TCP" and (c.b_port == 22 or c.a_port == 22):
            client = c.a_ip if c.b_port == 22 else c.b_ip
            server = c.b_ip if c.b_port == 22 else c.a_ip
            ssh_conns[(client, server)].append(c)

    for (src, dst, svc), nums in attempts.items():
        if len(nums) >= 6:
            out.append(Finding(
                "high", "Brute force",
                "%s brute force: %s → %s  (%d attempts)" % (svc, src, dst, len(nums)),
                "%d authentication attempts from %s against %s over %s.\n"
                "%d were rejected by the server.\n"
                "Credentials tried are visible in cleartext — see the Credentials tab."
                % (len(nums), src, dst, svc, fails.get((src, dst, svc), 0)),
                "%d login attempts" % len(nums), nums[:200]))

    for (client, server), convs in ssh_conns.items():
        if len(convs) >= 8 and sum(c.total_bytes for c in convs) / len(convs) < 6000:
            out.append(Finding(
                "medium", "Brute force",
                "Repeated short SSH sessions: %s → %s (%d)" % (client, server, len(convs)),
                "%d separate SSH connections, each ending after only a few kilobytes. "
                "That pattern is typical of an SSH password brute force (hydra, medusa) — "
                "the payload is encrypted, so the shape of the traffic is the evidence."
                % len(convs),
                "%d SSH connections" % len(convs),
                [convs[0].packets[0] + 1] if convs[0].packets else []))
    return out


# ---------------------------------------------------------------------------
# 3. flags
# ---------------------------------------------------------------------------

def detect_flags(packets, conversations):
    out = []
    seen = set()

    def add(sev, title, detail, evidence, pkts, stream=-1):
        k = (title, evidence)
        if k in seen:
            return
        seen.add(k)
        out.append(Finding(sev, "Flag", title, detail, evidence, pkts, stream))

    # direct hits in packet payloads
    for p in packets:
        pay = p.payload
        if not pay:
            continue
        for m in KNOWN_FLAG_RE.finditer(pay[:65536]):
            add("critical", "Flag in cleartext: %s" % _short(m.group(0), 60),
                "A flag-shaped string appears in packet %d (%s → %s, %s).\n"
                "Value: %s" % (p.number, p.src, p.dst, p.proto, _short(m.group(0), 200)),
                _short(m.group(0), 120), [p.number])
        if len(out) > 60:
            break

    # reassembled streams: encodings and generic patterns
    scanned = 0
    for conv in conversations:
        if scanned > 400:
            break
        for direction, blob in ((0, conv.data_ab()), (1, conv.data_ba())):
            if not blob:
                continue
            scanned += 1
            pkt = conv.packets[0] + 1 if conv.packets else 0
            sample = blob[:200000]

            for m in KNOWN_FLAG_RE.finditer(sample):
                add("critical", "Flag in stream %d: %s" % (conv.stream_id,
                                                           _short(m.group(0), 60)),
                    "Stream %d (%s) contains a flag once the segments are put back "
                    "together.\nValue: %s" % (conv.stream_id, conv.label(),
                                              _short(m.group(0), 200)),
                    _short(m.group(0), 120), [pkt], conv.stream_id)

            for m in GENERIC_FLAG_RE.finditer(sample):
                tok = m.group(0)
                if KNOWN_FLAG_RE.match(tok) or len(tok) > 170:
                    continue
                if b"{" in tok and (b"$" in tok or b"()" in tok or b";" in tok):
                    continue
                add("medium", "Possible flag format string",
                    "Stream %d (%s) contains a token shaped like a CTF flag "
                    "(`name{...}`). Confirm by eye — this pattern also matches code.\n"
                    "Value: %s" % (conv.stream_id, conv.label(), _short(tok, 200)),
                    _short(tok, 120), [pkt], conv.stream_id)

            # base64
            for m in B64_RE.finditer(sample[:100000]):
                raw = m.group(0)
                if len(raw) > 8000:
                    continue
                dec = _b64(raw)
                if not dec:
                    continue
                fm = KNOWN_FLAG_RE.search(dec)
                if fm:
                    add("critical", "Flag hidden in base64: %s" % _short(fm.group(0), 50),
                        "Stream %d (%s) carries base64 that decodes to a flag.\n"
                        "Encoded: %s\nDecoded: %s" % (
                            conv.stream_id, conv.label(), _short(raw, 90), _short(fm.group(0), 200)),
                        _short(fm.group(0), 120), [pkt], conv.stream_id)
                elif len(dec) >= 24 and printable_ratio(dec) > 0.9 and b" " in dec:
                    add("low", "Base64-encoded text in traffic",
                        "Stream %d (%s) contains a base64 blob that decodes to readable "
                        "text.\nDecoded: %s" % (conv.stream_id, conv.label(), _short(dec, 220)),
                        _short(dec, 100), [pkt], conv.stream_id)

            # hex
            for m in HEX_RE.finditer(sample[:60000]):
                try:
                    dec = binascii.unhexlify(m.group(0)[:len(m.group(0)) // 2 * 2])
                except binascii.Error:
                    continue
                fm = KNOWN_FLAG_RE.search(dec)
                if fm:
                    add("critical", "Flag hidden in hex encoding",
                        "Stream %d (%s) carries a hex string that decodes to a flag.\n"
                        "Decoded: %s" % (conv.stream_id, conv.label(), _short(fm.group(0), 200)),
                        _short(fm.group(0), 120), [pkt], conv.stream_id)

            # rot13
            rot = _rot13(sample[:40000])
            fm = KNOWN_FLAG_RE.search(rot)
            if fm:
                add("high", "Flag hidden with ROT13",
                    "Stream %d (%s) yields a flag after ROT13.\nDecoded: %s" % (
                        conv.stream_id, conv.label(), _short(fm.group(0), 200)),
                    _short(fm.group(0), 120), [pkt], conv.stream_id)

            # single-byte XOR brute force
            hit = _xor_bruteforce(sample[:16384])
            if hit:
                key, text = hit
                add("critical", "Flag recovered by single-byte XOR (key 0x%02x)" % key,
                    "Stream %d (%s) is obfuscated with a one-byte XOR. Decoding with "
                    "key 0x%02x reveals:\n%s" % (conv.stream_id, conv.label(), key,
                                                 _short(text, 200)),
                    _short(text, 120), [pkt], conv.stream_id)
    return out


def _b64(raw):
    try:
        pad = (-len(raw)) % 4
        dec = base64.b64decode(raw + b"=" * pad, validate=False)
    except (binascii.Error, ValueError):
        return b""
    if len(dec) < 6:
        return b""
    return dec


def _rot13(b):
    out = bytearray(b)
    for i, c in enumerate(out):
        if 97 <= c <= 122:
            out[i] = (c - 97 + 13) % 26 + 97
        elif 65 <= c <= 90:
            out[i] = (c - 65 + 13) % 26 + 65
    return bytes(out)


XOR_NEEDLES = (b"flag{", b"FLAG{", b"ctf{", b"CTF{", b"picoCTF{", b"HTB{", b"THM{")


def _xor_bruteforce(data):
    if len(data) < 8:
        return None
    for key in range(1, 256):
        dec = data.translate(_xor_table(key))
        for needle in XOR_NEEDLES:
            i = dec.find(needle)
            if i >= 0:
                end = dec.find(b"}", i)
                return key, dec[i:end + 1 if end > 0 else i + 120]
    return None


# ---------------------------------------------------------------------------
# 4. credentials
# ---------------------------------------------------------------------------

@dataclass
class Credential:
    proto: str
    server: str
    client: str
    username: str
    password: str
    packet: int
    note: str = ""


def extract_credentials(packets, conversations):
    creds = []
    ftp_state = {}

    for p in packets:
        pay = p.payload
        if not pay or len(pay) > 8192:
            continue
        proto = p.proto

        if proto in ("FTP", "POP3", "IMAP", "SMTP"):
            key = (p.src, p.dst)
            for line in pay.split(b"\r\n"):
                low = line.lower()
                if low.startswith(b"user "):
                    ftp_state[key] = (line[5:].decode("utf-8", "replace").strip(), p.number)
                elif low.startswith(b"pass "):
                    user, unum = ftp_state.pop(key, ("(unknown)", p.number))
                    creds.append(Credential(proto, p.dst, p.src, user,
                                            line[5:].decode("utf-8", "replace").strip(),
                                            p.number, "cleartext login"))
                elif low.startswith(b"login "):
                    parts = line.split(b" ")
                    if len(parts) >= 3:
                        creds.append(Credential("IMAP", p.dst, p.src,
                                                parts[1].decode("utf-8", "replace").strip('"'),
                                                parts[2].decode("utf-8", "replace").strip('"'),
                                                p.number, "IMAP LOGIN"))
                elif low.startswith(b"auth plain "):
                    dec = _b64(line[11:].strip())
                    parts = dec.split(b"\x00")
                    if len(parts) >= 3:
                        creds.append(Credential("SMTP", p.dst, p.src,
                                                parts[1].decode("utf-8", "replace"),
                                                parts[2].decode("utf-8", "replace"),
                                                p.number, "AUTH PLAIN (base64)"))
                elif low.startswith(b"auth ") and proto == "SMTP":
                    ftp_state[("smtp-auth", p.src, p.dst)] = ("", p.number)
                elif re.fullmatch(rb"[A-Za-z0-9+/=]{4,120}", line.strip() or b"x") and \
                        ("smtp-auth", p.src, p.dst) in ftp_state:
                    dec = _b64(line.strip())
                    if dec and printable_ratio(dec) > 0.9:
                        st = ftp_state[("smtp-auth", p.src, p.dst)]
                        if not st[0]:
                            ftp_state[("smtp-auth", p.src, p.dst)] = (
                                dec.decode("utf-8", "replace"), p.number)
                        else:
                            creds.append(Credential("SMTP", p.dst, p.src, st[0],
                                                    dec.decode("utf-8", "replace"),
                                                    p.number, "AUTH LOGIN (base64)"))
                            del ftp_state[("smtp-auth", p.src, p.dst)]

        elif proto == "HTTP":
            m = HTTP_BASIC_RE.search(pay)
            if m:
                dec = _b64(m.group(1)).decode("utf-8", "replace")
                user, _, pw = dec.partition(":")
                creds.append(Credential("HTTP Basic", p.dst, p.src, user, pw,
                                        p.number, "Authorization header (base64)"))
            m = HTTP_BEARER_RE.search(pay)
            if m:
                creds.append(Credential("HTTP Bearer", p.dst, p.src, "(token)",
                                        m.group(1).decode("utf-8", "replace")[:80],
                                        p.number, "Bearer token"))
            body = pay.split(b"\r\n\r\n", 1)
            for chunk in (pay.split(b"\r\n")[0], body[1] if len(body) > 1 else b""):
                found = {}
                for m in FORM_CRED_RE.finditer(chunk):
                    found[m.group(2).lower().decode()] = m.group(6).decode("utf-8", "replace")
                if found:
                    user = next((v for k, v in found.items()
                                 if k in ("user", "username", "login", "email")), "")
                    pw = next((v for k, v in found.items()
                               if k.startswith("pass") or k == "pwd"), "")
                    tok = next((v for k, v in found.items()
                                if "key" in k or k == "token"), "")
                    if user or pw or tok:
                        creds.append(Credential("HTTP form", p.dst, p.src,
                                                user or "(none)", pw or tok, p.number,
                                                "submitted parameters"))

        elif proto == "REDIS" and pay[:5].upper() == b"AUTH ":
            creds.append(Credential("Redis", p.dst, p.src, "(default)",
                                    pay[5:].decode("utf-8", "replace").strip(),
                                    p.number, "AUTH command"))
        elif proto == "SNMP":
            m = re.search(rb"\x04(.{1,20}?)\xa[0-5]", pay)
            if m and printable_ratio(m.group(1)) > 0.9:
                creds.append(Credential("SNMP", p.dst, p.src, "community",
                                        m.group(1).decode("utf-8", "replace"),
                                        p.number, "community string"))

    # Telnet: the client side of the stream is literally what the user typed —
    # first line is the login, second the password (the server never echoes it).
    for conv in conversations:
        if conv.proto != "TCP" or 23 not in (conv.a_port, conv.b_port):
            continue
        client_dir = 0 if conv.b_port == 23 else 1
        typed = conv.data_ab() if client_dir == 0 else conv.data_ba()
        typed = bytes(c for c in typed if 32 <= c < 127 or c in (10, 13))
        lines = [l for l in re.split(rb"[\r\n]+", typed) if l.strip()]
        if len(lines) >= 2 and all(len(l) < 40 for l in lines[:2]):
            creds.append(Credential("Telnet", conv.b_ip if client_dir == 0 else conv.a_ip,
                                    conv.a_ip if client_dir == 0 else conv.b_ip,
                                    lines[0].decode("utf-8", "replace"),
                                    lines[1].decode("utf-8", "replace"),
                                    conv.packets[0] + 1 if conv.packets else 0,
                                    "client keystrokes, stream %d" % conv.stream_id))
    return creds


def detect_credentials(packets, conversations):
    creds = extract_credentials(packets, conversations)
    if not creds:
        return []
    by_proto = Counter(c.proto for c in creds)
    lines = ["%d credential pair(s) were sent without encryption:" % len(creds), ""]
    for c in creds[:12]:
        lines.append("  %-12s %s → %s    %s : %s" % (
            c.proto, c.client, c.server, c.username or "(none)", c.password or "(none)"))
    if len(creds) > 12:
        lines.append("  … and %d more (see the Credentials tab)" % (len(creds) - 12))
    lines += ["", "Protocols involved: " + ", ".join("%s (%d)" % (k, v)
                                                     for k, v in by_proto.most_common())]
    return [Finding("critical", "Credentials",
                    "Cleartext credentials captured (%d)" % len(creds),
                    "\n".join(lines),
                    "%s" % ", ".join("%s:%s" % (c.username, c.password) for c in creds[:3]),
                    [c.packet for c in creds if c.packet][:60])]


# ---------------------------------------------------------------------------
# 5. DNS tunnelling / exfiltration
# ---------------------------------------------------------------------------

def detect_dns_tunnel(packets):
    out = []
    per_domain = defaultdict(lambda: {"labels": set(), "pkts": [], "len": 0,
                                      "types": Counter(), "ent": []})
    txt_replies = []
    for p in packets:
        if p.proto not in ("DNS", "MDNS"):
            continue
        for name in p.dns_names:
            parts = name.split(".")
            if len(parts) < 2:
                continue
            base = ".".join(parts[-2:])
            sub = ".".join(parts[:-2])
            d = per_domain[base]
            if sub:
                d["labels"].add(sub)
                d["len"] += len(sub)
                d["ent"].append(entropy(sub.encode()))
            d["pkts"].append(p.number)
        if "TXT" in p.info and "Response" in p.info:
            txt_replies.append(p.number)

    for base, d in per_domain.items():
        n = len(d["labels"])
        if n < 8:
            continue
        avg_len = d["len"] / max(1, n)
        avg_ent = sum(d["ent"]) / max(1, len(d["ent"]))
        longest = max(d["labels"], key=len)
        encoded = sum(1 for l in d["labels"]
                      if re.fullmatch(r"[A-Za-z0-9+/=_-]{16,}", l.split(".")[0] or "x"))
        score = (n >= 20) + (avg_len > 20) + (avg_ent > 3.2) + (encoded > n * 0.4)
        if score < 2:
            continue
        sev = "critical" if score >= 3 else "high"
        decoded = _decode_labels(d["labels"])
        detail = [
            "%d unique subdomains were queried under %s." % (n, base),
            "Average label length %.0f chars, average entropy %.2f bits/char." % (avg_len, avg_ent),
            "Longest label: %s" % longest[:110],
            "",
            "High-entropy, high-cardinality subdomains under one zone are how data leaves a "
            "network when only DNS is allowed (iodine, dnscat2, or a hand-rolled exfil script).",
        ]
        if decoded:
            detail += ["", "Decoded label content:", decoded[:600]]
        out.append(Finding(sev, "Exfiltration",
                           "DNS tunnelling / exfiltration via %s" % base,
                           "\n".join(detail),
                           "%d unique subdomains, entropy %.2f" % (n, avg_ent),
                           d["pkts"][:300]))
    if len(txt_replies) >= 10:
        out.append(Finding("medium", "Exfiltration",
                           "Unusual volume of DNS TXT records (%d)" % len(txt_replies),
                           "TXT is rarely used by normal clients but is the standard carrier "
                           "for DNS-based command channels and staged payloads.",
                           "%d TXT answers" % len(txt_replies), txt_replies[:200]))
    return out


def _seq_key(label):
    """Order chunks by any numeric label (tunnels usually carry a sequence number)."""
    for part in label.split("."):
        if part.isdigit():
            return (0, int(part), label)
    return (1, 0, label)


def _decode_labels(labels):
    chunks = []
    for lab in sorted(labels, key=_seq_key)[:40]:
        head = lab.split(".")[0]
        dec = _b64(head.encode()) if re.fullmatch(r"[A-Za-z0-9+/=]{8,}", head) else b""
        if not dec:
            try:
                dec = binascii.unhexlify(head) if re.fullmatch(r"(?:[0-9a-fA-F]{2}){4,}", head) else b""
            except binascii.Error:
                dec = b""
        if not dec and re.fullmatch(r"[A-Z2-7=]{8,}", head.upper()):
            try:
                dec = base64.b32decode(head.upper() + "=" * ((-len(head)) % 8))
            except (binascii.Error, ValueError):
                dec = b""
        if dec and printable_ratio(dec) > 0.85:
            chunks.append(dec.decode("utf-8", "replace"))
    return "".join(chunks)


# ---------------------------------------------------------------------------
# 6. ICMP tunnelling
# ---------------------------------------------------------------------------

def detect_icmp_tunnel(packets):
    payloads, nums = [], []
    for p in packets:
        if p.proto == "ICMP" and p.payload and len(p.payload) >= 8:
            payloads.append(p.payload)
            nums.append(p.number)
    if len(payloads) < 3:
        return []
    # normal ping payloads are a repeating byte pattern and identical across packets
    uniq = len({bytes(x) for x in payloads})
    texty = [x for x in payloads if printable_ratio(x) > 0.8]
    patterned = sum(1 for x in payloads if _is_ping_pattern(x))
    out = []
    if patterned >= len(payloads) * 0.7:
        return out
    if uniq >= max(3, len(payloads) * 0.5) and (texty or uniq > 8):
        joined = b"".join(texty)[:800]
        detail = ["%d ICMP echo packets carry %d distinct payloads." % (len(payloads), uniq),
                  "Standard ping fills the payload with a fixed incrementing pattern; varying "
                  "data means the echo field is being used as a transport (ptunnel, icmpsh, "
                  "or a CTF exfil channel)."]
        if joined:
            detail += ["", "Readable payload content:", _short(joined, 600)]
        flag = KNOWN_FLAG_RE.search(b"".join(payloads))
        if flag:
            detail += ["", "A flag is present in the ICMP data: " + _short(flag.group(0), 120)]
        out.append(Finding("high" if not flag else "critical", "Exfiltration",
                           "ICMP tunnelling — data hidden in ping payloads",
                           "\n".join(detail),
                           "%d distinct ICMP payloads" % uniq, nums[:300]))
    return out


def _is_ping_pattern(x):
    if len(x) < 16:
        return False
    body = x[8:] if len(x) > 8 else x
    inc = all((body[i] + 1) & 0xFF == body[i + 1] for i in range(min(len(body) - 1, 24)))
    same = len(set(body[:32])) <= 2
    return inc or same


# ---------------------------------------------------------------------------
# 7. web attacks
# ---------------------------------------------------------------------------

def detect_web_attacks(packets, conversations):
    out = []
    hits = defaultdict(list)
    checks = [("SQL injection", SQLI_RE, "high"),
              ("Path traversal / LFI", TRAVERSAL_RE, "high"),
              ("Command injection / reverse shell", CMDI_RE, "critical"),
              ("Cross-site scripting", XSS_RE, "medium"),
              ("Web shell", WEBSHELL_RE, "critical")]
    samples = {}
    uas = Counter()
    ua_pkts = defaultdict(list)
    codes = Counter()
    dirbust = defaultdict(set)

    for p in packets:
        pay = p.payload
        if not pay or p.proto not in ("HTTP", "HTTP-ALT", "HTTP-PROXY"):
            continue
        head = pay[:4096]
        for name, rx, sev in checks:
            m = rx.search(head)
            if m:
                hits[(name, sev)].append(p.number)
                samples.setdefault((name, sev), (p, _short(head.split(b"\r\n")[0], 180)))
        m = re.search(rb"(?im)^User-Agent:\s*(.+)$", head)
        if m:
            ua = m.group(1).strip()
            uas[ua] += 1
            if BAD_UA_RE.search(ua):
                ua_pkts[ua].append(p.number)
        m = re.match(rb"(GET|POST|HEAD|PUT) (\S+)", head)
        if m:
            dirbust[(p.src, p.dst)].add(m.group(2))
        if head.startswith(b"HTTP/1."):
            parts = head.split(b" ")
            if len(parts) > 1 and parts[1].isdigit():
                codes[int(parts[1])] += 1

    for (name, sev), nums in hits.items():
        pkt, line = samples[(name, sev)]
        out.append(Finding(sev, "Web attack",
                           "%s in HTTP traffic (%d request(s))" % (name, len(nums)),
                           "Pattern matched on %d HTTP message(s), first at packet %d "
                           "(%s → %s).\n\nExample:\n%s" % (
                               len(nums), pkt.number, pkt.src, pkt.dst, line),
                           line[:110], nums[:200]))

    for ua, nums in ua_pkts.items():
        tool = _short(ua, 90)
        out.append(Finding("medium" if b"curl" in ua.lower() or b"wget" in ua.lower() else "high",
                           "Web attack", "Scanner/automation User-Agent: %s" % tool,
                           "%d request(s) advertised the User-Agent %r. Security scanners and "
                           "scripted clients announce themselves here unless deliberately "
                           "changed." % (len(nums), tool),
                           tool, nums[:200]))

    for (src, dst), paths in dirbust.items():
        if len(paths) >= 30 and codes.get(404, 0) >= 10:
            out.append(Finding("high", "Recon",
                               "Directory brute force: %s → %s (%d paths)" % (src, dst, len(paths)),
                               "%d distinct URL paths were requested and the server answered "
                               "with many 404s — content discovery with gobuster/dirb/ffuf.\n"
                               "Sample: %s" % (len(paths), ", ".join(
                                   sorted(p.decode("utf-8", "replace") for p in list(paths)[:10]))),
                               "%d paths, %d × 404" % (len(paths), codes.get(404, 0)), []))
    return out


# ---------------------------------------------------------------------------
# 8. keys, tokens, shells, files
# ---------------------------------------------------------------------------

def detect_secrets(conversations):
    out = []
    for conv in conversations:
        for blob in (conv.data_ab(), conv.data_ba()):
            if not blob:
                continue
            pkt = conv.packets[0] + 1 if conv.packets else 0
            if PEM_RE.search(blob):
                out.append(Finding("critical", "Secrets",
                                   "Private key transmitted in cleartext",
                                   "Stream %d (%s) contains a PEM-encoded private key. "
                                   "Anything encrypted with the matching certificate can now "
                                   "be decrypted." % (conv.stream_id, conv.label()),
                                   "-----BEGIN PRIVATE KEY-----", [pkt], conv.stream_id))
            for m in AWS_RE.finditer(blob[:200000]):
                out.append(Finding("critical", "Secrets", "AWS access key ID exposed",
                                   "Stream %d (%s) contains %s." % (
                                       conv.stream_id, conv.label(),
                                       m.group(0).decode()),
                                   m.group(0).decode(), [pkt], conv.stream_id))
            m = JWT_RE.search(blob[:200000])
            if m:
                payload = m.group(0).split(b".")[1]
                dec = _b64(payload)
                out.append(Finding("medium", "Secrets", "JSON Web Token in cleartext",
                                   "Stream %d (%s) carries a JWT.\nHeader/claims: %s" % (
                                       conv.stream_id, conv.label(), _short(dec, 300)),
                                   _short(m.group(0), 80), [pkt], conv.stream_id))
    return _dedupe(out)


def detect_files(carved):
    out = []
    interesting = [f for f in carved if f.ext not in ("html", "txt", "css", "js", "json")]
    for f in interesting[:25]:
        sev = "high" if f.ext in ("exe", "elf", "zip", "macho", "class", "pem", "sqlite") else "medium"
        out.append(Finding(sev, "File transfer",
                           "%s transferred over the network (%s, %s)" % (
                               f.kind, f.name, _size(f.size)),
                           "A %s was carried in stream %d.\nSource: %s\nSize: %s\n\n"
                           "Extract it from the Files tab and inspect it — transferred files "
                           "are where CTF challenges hide the answer (archives, images with "
                           "appended data, binaries)." % (
                               f.kind, f.stream_id, f.source, _size(f.size)),
                           f.name, [f.packet + 1] if f.packet else [], f.stream_id))
    return out


SHELL_MARKERS = [
    (rb"(?i)uid=\d+\(\w+\)\s+gid=\d+", "output of `id` — a shell command ran"),
    (rb"(?i)\$ (whoami|ls|cat|pwd|id|uname)\b", "interactive shell prompt with commands"),
    (rb"(?i)# (whoami|ls|cat|pwd|id|uname)\b", "root shell prompt with commands"),
    (rb"(?i)bash-\d\.\d[#$]", "bash prompt"),
    (rb"(?i)Microsoft Windows \[Version", "Windows cmd.exe banner"),
    (rb"(?i)root@[\w.-]+:[^\r\n]*[#$]", "root prompt"),
    (rb"(?i)/bin/(ba)?sh\s*-i", "interactive shell spawn"),
    (rb"(?i)python -c ['\"]import (pty|socket)", "python reverse-shell one-liner"),
]


def detect_shells(packets, conversations):
    out = []
    for conv in conversations:
        if conv.proto != "TCP":
            continue
        blob = conv.data_ab() + b"\n" + conv.data_ba()
        if not blob or len(blob) < 12:
            continue
        pkt = conv.packets[0] + 1 if conv.packets else 0
        found = []
        for rx, desc in SHELL_MARKERS:
            m = re.search(rx, blob[:200000])
            if m:
                found.append((desc, _short(m.group(0), 90)))
        if found:
            port = conv.b_port if conv.b_port not in (0,) else conv.a_port
            note = SUSPICIOUS_PORTS.get(conv.b_port) or SUSPICIOUS_PORTS.get(conv.a_port)
            detail = ["Stream %d (%s) looks like an interactive command session." % (
                conv.stream_id, conv.label()), ""]
            detail += ["  • %s   →  %s" % (d, ev) for d, ev in found]
            if note:
                detail += ["", "Destination port %d is %s." % (port, note)]
            detail += ["", "Open the stream in Follow Stream to read the whole session."]
            out.append(Finding("critical", "Shell session",
                               "Remote shell session on port %d (stream %d)" % (port, conv.stream_id),
                               "\n".join(detail), found[0][1], [pkt], conv.stream_id))
    return out


def detect_beaconing(conversations, packets):
    out = []
    by_pair = defaultdict(list)
    for p in packets:
        if p.transport == "TCP" and (p.tcp_flags & 0x3F) == 0x02:
            by_pair[(p.src, p.dst, p.dport)].append(p.ts)
        elif p.transport == "UDP" and p.dport not in (53, 5353, 123, 137, 138):
            by_pair[(p.src, p.dst, p.dport)].append(p.ts)
    for (src, dst, port), times in by_pair.items():
        if len(times) < 6:
            continue
        times.sort()
        gaps = [b - a for a, b in zip(times, times[1:]) if b - a > 0.05]
        if len(gaps) < 5:
            continue
        avg = sum(gaps) / len(gaps)
        if avg < 0.4:
            continue
        jitter = math.sqrt(sum((g - avg) ** 2 for g in gaps) / len(gaps)) / avg
        if jitter < 0.15:
            out.append(Finding("high", "C2 / beaconing",
                               "Regular beaconing: %s → %s:%d every %.1f s" % (
                                   src, dst, port, avg),
                               "%d connections at a near-constant interval of %.2f s "
                               "(jitter %.0f%%). Humans and normal applications do not "
                               "produce metronome traffic — implants do." % (
                                   len(times), avg, jitter * 100),
                               "interval %.2f s, jitter %.0f%%" % (avg, jitter * 100), []))
    return out


def detect_plaintext(packets, conversations):
    used = Counter()
    pkts = defaultdict(list)
    for p in packets:
        if p.proto in PLAINTEXT_PROTOS:
            used[p.proto] += 1
            if len(pkts[p.proto]) < 100:
                pkts[p.proto].append(p.number)
    if not used:
        return []
    lines = ["Unencrypted application protocols carried real traffic in this capture:", ""]
    for proto, count in used.most_common():
        lines.append("  %-8s %6d packets   (port %d)" % (proto, count, PLAINTEXT_PROTOS[proto]))
    lines += ["", "Everything above is readable by anyone on the path — including the "
                  "contents of the Credentials and Files tabs."]
    allp = [n for v in pkts.values() for n in v][:200]
    return [Finding("medium", "Plaintext protocol",
                    "Unencrypted protocols in use (%s)" % ", ".join(used),
                    "\n".join(lines), ", ".join(used), allp)]


def detect_oddities(packets, conversations, meta):
    out = []
    port_hits = defaultdict(list)
    for conv in conversations:
        for port in (conv.a_port, conv.b_port):
            if port in SUSPICIOUS_PORTS and conv.total_bytes > 0:
                port_hits[port].append(conv)
    for port, convs in port_hits.items():
        pkt = convs[0].packets[0] + 1 if convs[0].packets else 0
        out.append(Finding("high", "Anomaly",
                           "Traffic on port %d (%s)" % (port, SUSPICIOUS_PORTS[port]),
                           "%d conversation(s) used port %d, associated with %s.\n"
                           "Endpoints: %s" % (len(convs), port, SUSPICIOUS_PORTS[port],
                                              ", ".join(c.label() for c in convs[:4])),
                           SUSPICIOUS_PORTS[port], [pkt], convs[0].stream_id))

    big = [c for c in conversations if c.bytes_ab > 2_000_000 and c.bytes_ab > c.bytes_ba * 20]
    for c in big[:5]:
        out.append(Finding("medium", "Exfiltration",
                           "Large one-way upload: %s (%s)" % (c.label(), _size(c.bytes_ab)),
                           "%s was sent from %s to %s while only %s came back. A strongly "
                           "asymmetric outbound flow is what data theft looks like on the "
                           "wire." % (_size(c.bytes_ab), c.a_ip, c.b_ip, _size(c.bytes_ba)),
                           _size(c.bytes_ab), [c.packets[0] + 1] if c.packets else [],
                           c.stream_id))

    malformed = [p.number for p in packets if p.error]
    if len(malformed) > 3:
        out.append(Finding("low", "Anomaly", "Malformed frames (%d)" % len(malformed),
                           "%d frames could not be fully dissected. Truncated captures are "
                           "normal (snaplen), but deliberately malformed packets are also a "
                           "CTF hiding place — check the hex view." % len(malformed),
                           "%d frames" % len(malformed), malformed[:100]))
    if meta.get("truncated"):
        out.append(Finding("low", "Anomaly", "Capture file is truncated",
                           "The last packet record runs past the end of the file. The capture "
                           "was cut short — later evidence may be missing.", "", []))
    return _dedupe(out)


def _dedupe(findings):
    seen, out = set(), []
    for f in findings:
        k = (f.title, f.evidence)
        if k in seen:
            continue
        seen.add(k)
        out.append(f)
    return out


def _size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return "%.0f %s" % (n, unit) if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024.0
    return "%d B" % n


# ---------------------------------------------------------------------------
# verdict
# ---------------------------------------------------------------------------

def verdict(findings):
    """One-line, plain-language answer to 'what is in this capture?'"""
    scans = [f for f in findings if f.category in ("Port scan", "Network sweep")]
    crit = [f for f in findings if f.severity == "critical"]
    high = [f for f in findings if f.severity == "high"]
    if scans:
        head = "SCAN DETECTED"
        body = scans[0].title
        if len(scans) > 1:
            body += "  (+%d more scan finding%s)" % (len(scans) - 1,
                                                     "" if len(scans) == 2 else "s")
        level = "critical"
    elif crit:
        head = "MALICIOUS / SENSITIVE CONTENT"
        body = crit[0].title
        level = "critical"
    elif high:
        head = "SUSPICIOUS ACTIVITY"
        body = high[0].title
        level = "high"
    elif findings:
        head = "NOTHING CRITICAL"
        body = "%d informational finding(s); no scan or attack pattern matched." % len(findings)
        level = "medium"
    else:
        head = "CLEAN"
        body = "No scan, attack, credential or flag pattern was found in this capture."
        level = "low"
    return head, body, level
