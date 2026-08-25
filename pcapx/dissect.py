"""Protocol dissection: turns raw frames into layered, human-readable packets."""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# well-known names
# ---------------------------------------------------------------------------

IP_PROTOS = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE",
    50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF", 132: "SCTP",
}

ETHERTYPES = {
    0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6", 0x8100: "802.1Q VLAN",
    0x88CC: "LLDP", 0x8847: "MPLS", 0x8863: "PPPoE-D", 0x8864: "PPPoE-S",
}

PORT_SERVICES = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 88: "KERBEROS",
    110: "POP3", 111: "RPC", 123: "NTP", 135: "MSRPC", 137: "NBNS",
    138: "NBDS", 139: "NBSS", 143: "IMAP", 161: "SNMP", 162: "SNMP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 500: "ISAKMP",
    514: "SYSLOG", 587: "SMTP", 636: "LDAPS", 873: "RSYNC", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1433: "MSSQL", 1521: "ORACLE",
    1723: "PPTP", 1883: "MQTT", 2049: "NFS", 2375: "DOCKER", 3128: "SQUID",
    3306: "MYSQL", 3389: "RDP", 4444: "METASPLOIT", 5060: "SIP",
    5222: "XMPP", 5353: "MDNS", 5432: "POSTGRES", 5555: "ADB",
    5900: "VNC", 6000: "X11", 6379: "REDIS", 6667: "IRC", 8000: "HTTP-ALT",
    8080: "HTTP-PROXY", 8443: "HTTPS-ALT", 8888: "HTTP-ALT", 9001: "TOR",
    9200: "ELASTIC", 11211: "MEMCACHED", 27017: "MONGODB", 31337: "ELITE",
}

ICMP_TYPES = {
    0: "Echo Reply", 3: "Destination Unreachable", 4: "Source Quench",
    5: "Redirect", 8: "Echo Request", 9: "Router Advertisement",
    10: "Router Solicitation", 11: "Time Exceeded", 12: "Parameter Problem",
    13: "Timestamp Request", 14: "Timestamp Reply", 17: "Address Mask Request",
    18: "Address Mask Reply",
}

DNS_TYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 13: "HINFO", 15: "MX",
    16: "TXT", 17: "RP", 24: "SIG", 25: "KEY", 28: "AAAA", 29: "LOC",
    33: "SRV", 35: "NAPTR", 39: "DNAME", 41: "OPT", 43: "DS", 46: "RRSIG",
    47: "NSEC", 48: "DNSKEY", 52: "TLSA", 65: "HTTPS", 99: "SPF",
    252: "AXFR", 255: "ANY",
}

TCP_FLAG_BITS = [
    (0x100, "NS"), (0x80, "CWR"), (0x40, "ECE"), (0x20, "URG"),
    (0x10, "ACK"), (0x08, "PSH"), (0x04, "RST"), (0x02, "SYN"), (0x01, "FIN"),
]


def tcp_flag_str(flags):
    names = [n for bit, n in TCP_FLAG_BITS if flags & bit]
    return ", ".join(names) if names else "none"


def service_name(port):
    return PORT_SERVICES.get(port, "")


# ---------------------------------------------------------------------------
# packet model
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class Layer:
    name: str
    fields: list = field(default_factory=list)   # list[(label, value)]
    offset: int = 0
    length: int = 0


@dataclass(slots=True)
class Packet:
    index: int
    number: int
    ts: float
    caplen: int
    wirelen: int
    raw: bytes
    linktype: int
    layers: list = field(default_factory=list)
    src: str = ""
    dst: str = ""
    eth_src: str = ""
    eth_dst: str = ""
    sport: int = 0
    dport: int = 0
    ip_proto: int = 0
    proto: str = ""          # highest-level protocol name, shown in the list
    info: str = ""
    tcp_flags: int = 0
    seq: int = 0
    ack: int = 0
    payload: bytes = b""     # application-layer bytes
    payload_off: int = 0
    ip_ver: int = 0
    ttl: int = 0
    stream_key: tuple = ()
    error: str = ""
    dns_names: list = field(default_factory=list)

    @property
    def transport(self):
        return IP_PROTOS.get(self.ip_proto, "")

    def has_layer(self, name):
        return any(l.name == name for l in self.layers)


def mac(b):
    return ":".join("%02x" % x for x in b)


def ipv4(b):
    return "%d.%d.%d.%d" % tuple(b)


def ipv6(b):
    try:
        return socket.inet_ntop(socket.AF_INET6, b)
    except (OSError, ValueError):
        return b.hex()


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def dissect(rp):
    """Dissect a :class:`reader.RawPacket` into a :class:`Packet`."""
    pkt = Packet(index=rp.index, number=rp.index + 1, ts=rp.ts, caplen=rp.caplen,
                 wirelen=rp.wirelen, raw=rp.data, linktype=rp.linktype)
    pkt.proto = "RAW"
    pkt.info = "%d bytes captured" % rp.caplen
    try:
        _link(pkt, rp.data, rp.linktype)
    except (struct.error, IndexError, ValueError) as exc:
        pkt.error = "malformed frame: %s" % exc
        pkt.info = "[malformed] " + pkt.info
    if not pkt.src:
        pkt.src, pkt.dst = pkt.eth_src, pkt.eth_dst
    return pkt


# ---------------------------------------------------------------------------
# link layer
# ---------------------------------------------------------------------------

def _link(pkt, data, linktype):
    if linktype == 1:
        return _ethernet(pkt, data, 0)
    if linktype in (12, 101, 228, 229):
        ver = (data[0] >> 4) if data else 4
        return _ipv6(pkt, data, 0) if ver == 6 else _ipv4(pkt, data, 0)
    if linktype == 0:                                   # BSD loopback
        if len(data) < 4:
            return
        fam = struct.unpack("<I", data[:4])[0]
        pkt.layers.append(Layer("Loopback", [("Address family", str(fam))], 0, 4))
        return _ipv6(pkt, data, 4) if fam in (24, 28, 30) else _ipv4(pkt, data, 4)
    if linktype == 113:                                 # Linux cooked capture
        if len(data) < 16:
            return
        ptype, _at, _al, addr, proto = struct.unpack(">HHH8sH", data[:16])
        pkt.eth_src = mac(addr[:6])
        pkt.layers.append(Layer("Linux cooked capture", [
            ("Packet type", str(ptype)), ("Source", mac(addr[:6])),
            ("Protocol", "0x%04x" % proto)], 0, 16))
        return _ethertype(pkt, data, 16, proto)
    if linktype == 276:                                 # SLL2
        if len(data) < 20:
            return
        proto = struct.unpack(">H", data[:2])[0]
        pkt.layers.append(Layer("Linux cooked v2", [("Protocol", "0x%04x" % proto)], 0, 20))
        return _ethertype(pkt, data, 20, proto)
    pkt.layers.append(Layer("Link layer", [("Linktype", str(linktype))], 0, len(data)))


def _ethernet(pkt, data, off):
    if len(data) - off < 14:
        raise ValueError("short ethernet header")
    dst, src, etype = struct.unpack(">6s6sH", data[off:off + 14])
    pkt.eth_dst, pkt.eth_src = mac(dst), mac(src)
    layer = Layer("Ethernet II", [
        ("Destination", mac(dst)),
        ("Source", mac(src)),
        ("Type", "%s (0x%04x)" % (ETHERTYPES.get(etype, "Unknown"), etype)),
    ], off, 14)
    pkt.layers.append(layer)
    off += 14
    while etype in (0x8100, 0x88A8) and len(data) - off >= 4:
        tci, etype = struct.unpack(">HH", data[off:off + 4])
        pkt.layers.append(Layer("802.1Q VLAN", [
            ("Priority", str(tci >> 13)),
            ("VLAN ID", str(tci & 0x0FFF)),
            ("Type", "0x%04x" % etype)], off, 4))
        off += 4
    _ethertype(pkt, data, off, etype)


def _ethertype(pkt, data, off, etype):
    if etype == 0x0800:
        _ipv4(pkt, data, off)
    elif etype == 0x86DD:
        _ipv6(pkt, data, off)
    elif etype == 0x0806:
        _arp(pkt, data, off)
    elif etype <= 1500:
        pkt.proto = "802.3"
        pkt.info = "IEEE 802.3 length %d" % etype
    else:
        pkt.proto = ETHERTYPES.get(etype, "0x%04x" % etype)
        pkt.info = "%s frame" % pkt.proto


# ---------------------------------------------------------------------------
# network layer
# ---------------------------------------------------------------------------

def _arp(pkt, data, off):
    if len(data) - off < 28:
        raise ValueError("short ARP")
    hw, pr, hl, pl, op = struct.unpack(">HHBBH", data[off:off + 8])
    sha = data[off + 8:off + 8 + hl]
    spa = data[off + 8 + hl:off + 8 + hl + pl]
    tha = data[off + 8 + hl + pl:off + 8 + 2 * hl + pl]
    tpa = data[off + 8 + 2 * hl + pl:off + 8 + 2 * hl + 2 * pl]
    sip = ipv4(spa) if pl == 4 else spa.hex()
    tip = ipv4(tpa) if pl == 4 else tpa.hex()
    ops = {1: "request", 2: "reply", 3: "RARP request", 4: "RARP reply"}
    pkt.layers.append(Layer("ARP", [
        ("Hardware type", "Ethernet (%d)" % hw),
        ("Protocol type", "0x%04x" % pr),
        ("Opcode", "%s (%d)" % (ops.get(op, "unknown"), op)),
        ("Sender MAC", mac(sha) if hl == 6 else sha.hex()),
        ("Sender IP", sip),
        ("Target MAC", mac(tha) if hl == 6 else tha.hex()),
        ("Target IP", tip),
    ], off, 28))
    pkt.proto = "ARP"
    pkt.src, pkt.dst = sip, tip
    if op == 1:
        pkt.info = "Who has %s?  Tell %s" % (tip, sip)
        if sip == tip:
            pkt.info = "Gratuitous ARP for %s" % sip
    elif op == 2:
        pkt.info = "%s is at %s" % (sip, mac(sha) if hl == 6 else sha.hex())
    else:
        pkt.info = "ARP opcode %d" % op


def _ipv4(pkt, data, off):
    if len(data) - off < 20:
        raise ValueError("short IPv4 header")
    ver_ihl, tos, tlen, ident, frag, ttl, proto, csum, src, dst = struct.unpack(
        ">BBHHHBBH4s4s", data[off:off + 20])
    ihl = (ver_ihl & 0x0F) * 4
    flags = frag >> 13
    frag_off = (frag & 0x1FFF) * 8
    pkt.ip_ver, pkt.ttl, pkt.ip_proto = 4, ttl, proto
    pkt.src, pkt.dst = ipv4(src), ipv4(dst)
    fl = []
    if flags & 0x2:
        fl.append("DF")
    if flags & 0x1:
        fl.append("MF")
    pkt.layers.append(Layer("Internet Protocol v4", [
        ("Version", "4"),
        ("Header length", "%d bytes" % ihl),
        ("DSCP / ECN", "0x%02x" % tos),
        ("Total length", str(tlen)),
        ("Identification", "0x%04x (%d)" % (ident, ident)),
        ("Flags", ("%s (0x%x)" % ("+".join(fl), flags)) if fl else "0x0"),
        ("Fragment offset", str(frag_off)),
        ("Time to live", str(ttl)),
        ("Protocol", "%s (%d)" % (IP_PROTOS.get(proto, "?"), proto)),
        ("Header checksum", "0x%04x" % csum),
        ("Source", ipv4(src)),
        ("Destination", ipv4(dst)),
    ], off, ihl))
    body_end = off + tlen if 0 < tlen <= len(data) - off else len(data)
    if frag_off > 0:
        pkt.proto = "IPv4 frag"
        pkt.info = "Fragmented IP protocol (proto=%s off=%d)" % (
            IP_PROTOS.get(proto, proto), frag_off)
        pkt.payload = data[off + ihl:body_end]
        pkt.payload_off = off + ihl
        return
    _transport(pkt, data, off + ihl, body_end, proto)


def _ipv6(pkt, data, off):
    if len(data) - off < 40:
        raise ValueError("short IPv6 header")
    vtf, plen, nh, hlim = struct.unpack(">IHBB", data[off:off + 8])
    src, dst = data[off + 8:off + 24], data[off + 24:off + 40]
    pkt.ip_ver, pkt.ttl, pkt.ip_proto = 6, hlim, nh
    pkt.src, pkt.dst = ipv6(src), ipv6(dst)
    pkt.layers.append(Layer("Internet Protocol v6", [
        ("Version", "6"),
        ("Traffic class", "0x%02x" % ((vtf >> 20) & 0xFF)),
        ("Flow label", "0x%05x" % (vtf & 0xFFFFF)),
        ("Payload length", str(plen)),
        ("Next header", "%s (%d)" % (IP_PROTOS.get(nh, "?"), nh)),
        ("Hop limit", str(hlim)),
        ("Source", ipv6(src)),
        ("Destination", ipv6(dst)),
    ], off, 40))
    off += 40
    end = min(len(data), off + plen) if plen else len(data)
    # walk extension headers
    for _ in range(8):
        if nh in (0, 43, 60) and end - off >= 8:
            nxt, hlen = data[off], (data[off + 1] + 1) * 8
            pkt.layers.append(Layer("IPv6 extension header",
                                    [("Next header", str(nxt)), ("Length", str(hlen))], off, hlen))
            off += hlen
            nh = nxt
            continue
        break
    pkt.ip_proto = nh
    _transport(pkt, data, off, end, nh)


# ---------------------------------------------------------------------------
# transport layer
# ---------------------------------------------------------------------------

def _transport(pkt, data, off, end, proto):
    if proto == 6:
        _tcp(pkt, data, off, end)
    elif proto == 17:
        _udp(pkt, data, off, end)
    elif proto == 1:
        _icmp(pkt, data, off, end)
    elif proto == 58:
        _icmpv6(pkt, data, off, end)
    elif proto == 2:
        pkt.proto, pkt.info = "IGMP", "Internet Group Management Protocol"
    else:
        pkt.proto = IP_PROTOS.get(proto, "IP proto %d" % proto)
        pkt.info = "%s payload, %d bytes" % (pkt.proto, max(0, end - off))
        pkt.payload, pkt.payload_off = data[off:end], off


def _tcp(pkt, data, off, end):
    if len(data) - off < 20:
        raise ValueError("short TCP header")
    sport, dport, seq, ack, off_flags, win, csum, urg = struct.unpack(
        ">HHIIHHHH", data[off:off + 20])
    hlen = (off_flags >> 12) * 4
    flags = off_flags & 0x1FF
    pkt.sport, pkt.dport, pkt.seq, pkt.ack, pkt.tcp_flags = sport, dport, seq, ack, flags
    opts = data[off + 20:off + hlen]
    fields = [
        ("Source port", _port(sport)),
        ("Destination port", _port(dport)),
        ("Sequence number", str(seq)),
        ("Acknowledgement number", str(ack)),
        ("Header length", "%d bytes" % hlen),
        ("Flags", "%s (0x%03x)" % (tcp_flag_str(flags), flags)),
        ("Window size", str(win)),
        ("Checksum", "0x%04x" % csum),
    ]
    if urg:
        fields.append(("Urgent pointer", str(urg)))
    if opts:
        fields.append(("Options", _tcp_options(opts)))
    pkt.layers.append(Layer("Transmission Control Protocol", fields, off, hlen))
    payload = data[off + hlen:end]
    pkt.payload, pkt.payload_off = payload, off + hlen
    pkt.proto = "TCP"
    pkt.info = "%d → %d [%s] Seq=%d Ack=%d Win=%d Len=%d" % (
        sport, dport, tcp_flag_str(flags), seq, ack, win, len(payload))
    if payload:
        _application(pkt, payload, sport, dport, "TCP")


def _tcp_options(opts):
    names = {0: "EOL", 1: "NOP", 2: "MSS", 3: "WScale", 4: "SACK-perm",
             5: "SACK", 8: "Timestamps", 28: "UTO", 29: "AO", 34: "TFO"}
    out, i = [], 0
    while i < len(opts):
        kind = opts[i]
        if kind in (0, 1):
            out.append(names[kind])
            i += 1
            continue
        if i + 1 >= len(opts):
            break
        ln = opts[i + 1]
        if ln < 2:
            break
        val = opts[i + 2:i + ln]
        label = names.get(kind, "opt%d" % kind)
        if kind == 2 and len(val) == 2:
            label += "=%d" % struct.unpack(">H", val)[0]
        elif kind == 3 and len(val) == 1:
            label += "=%d" % val[0]
        out.append(label)
        i += ln
    return ", ".join(out)


def _udp(pkt, data, off, end):
    if len(data) - off < 8:
        raise ValueError("short UDP header")
    sport, dport, ulen, csum = struct.unpack(">HHHH", data[off:off + 8])
    pkt.sport, pkt.dport = sport, dport
    pkt.layers.append(Layer("User Datagram Protocol", [
        ("Source port", _port(sport)),
        ("Destination port", _port(dport)),
        ("Length", str(ulen)),
        ("Checksum", "0x%04x" % csum),
    ], off, 8))
    stop = min(end, off + ulen) if 8 <= ulen <= end - off else end
    payload = data[off + 8:stop]
    pkt.payload, pkt.payload_off = payload, off + 8
    pkt.proto = "UDP"
    pkt.info = "%d → %d  Len=%d" % (sport, dport, len(payload))
    if payload:
        _application(pkt, payload, sport, dport, "UDP")


def _icmp(pkt, data, off, end):
    if len(data) - off < 4:
        raise ValueError("short ICMP")
    typ, code, csum = struct.unpack(">BBH", data[off:off + 4])
    rest = data[off + 4:end]
    fields = [("Type", "%d (%s)" % (typ, ICMP_TYPES.get(typ, "Unknown"))),
              ("Code", str(code)), ("Checksum", "0x%04x" % csum)]
    pkt.proto = "ICMP"
    info = ICMP_TYPES.get(typ, "Type %d" % typ)
    if typ in (0, 8) and len(rest) >= 4:
        ident, seqn = struct.unpack(">HH", rest[:4])
        fields += [("Identifier", str(ident)), ("Sequence", str(seqn))]
        info += "  id=0x%04x seq=%d" % (ident, seqn)
        pkt.payload, pkt.payload_off = rest[4:], off + 8
    else:
        pkt.payload, pkt.payload_off = rest, off + 4
    if pkt.payload:
        fields.append(("Data", "%d bytes" % len(pkt.payload)))
    pkt.layers.append(Layer("Internet Control Message Protocol", fields, off, 4))
    pkt.info = info


def _icmpv6(pkt, data, off, end):
    if len(data) - off < 4:
        raise ValueError("short ICMPv6")
    typ, code, csum = struct.unpack(">BBH", data[off:off + 4])
    names = {1: "Destination Unreachable", 2: "Packet Too Big", 3: "Time Exceeded",
             128: "Echo Request", 129: "Echo Reply", 133: "Router Solicitation",
             134: "Router Advertisement", 135: "Neighbor Solicitation",
             136: "Neighbor Advertisement", 143: "Multicast Listener Report"}
    pkt.proto = "ICMPv6"
    pkt.info = names.get(typ, "Type %d" % typ)
    pkt.payload, pkt.payload_off = data[off + 4:end], off + 4
    pkt.layers.append(Layer("ICMPv6", [
        ("Type", "%d (%s)" % (typ, names.get(typ, "Unknown"))),
        ("Code", str(code)), ("Checksum", "0x%04x" % csum)], off, 4))


def _port(p):
    svc = PORT_SERVICES.get(p)
    return "%d (%s)" % (p, svc) if svc else str(p)


# ---------------------------------------------------------------------------
# application layer
# ---------------------------------------------------------------------------

HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ",
                b"PATCH ", b"TRACE ", b"CONNECT ", b"PROPFIND ")


def _application(pkt, payload, sport, dport, l4):
    ports = (sport, dport)
    if l4 == "UDP" and (53 in ports or 5353 in ports or 5355 in ports):
        return _dns(pkt, payload, "MDNS" if 5353 in ports else "DNS")
    if l4 == "TCP" and 53 in ports and len(payload) > 2:
        return _dns(pkt, payload[2:], "DNS")
    if l4 == "UDP" and (67 in ports or 68 in ports):
        return _dhcp(pkt, payload)
    if l4 == "UDP" and 123 in ports:
        pkt.proto, pkt.info = "NTP", "NTP %s" % ("client" if dport == 123 else "server")
        return
    if l4 == "UDP" and 69 in ports:
        return _tftp(pkt, payload)
    if l4 == "UDP" and 514 in ports:
        pkt.proto = "SYSLOG"
        pkt.info = _oneline(payload, 110)
        return
    if l4 == "UDP" and 161 in ports:
        pkt.proto, pkt.info = "SNMP", "SNMP message, %d bytes" % len(payload)
        return

    if l4 != "TCP":
        if _is_texty(payload):
            pkt.info = "%s  |  %s" % (pkt.info, _oneline(payload, 90))
        return

    # --- TCP application protocols ---
    if payload.startswith(HTTP_METHODS):
        pkt.proto = "HTTP"
        pkt.info = _oneline(payload, 120)
        return
    if payload.startswith(b"HTTP/1.") or payload.startswith(b"HTTP/2"):
        pkt.proto = "HTTP"
        line = _oneline(payload, 90)
        ctype = _header(payload, b"content-type")
        pkt.info = line + ("   [%s]" % ctype if ctype else "")
        return
    if len(payload) >= 3 and payload[0] in (0x14, 0x15, 0x16, 0x17) and payload[1] == 0x03:
        return _tls(pkt, payload)
    if 443 in ports or 993 in ports or 995 in ports or 8443 in ports:
        pkt.proto = "TLS"
        pkt.info = "Encrypted application data, %d bytes" % len(payload)
        return
    if 22 in ports:
        pkt.proto = "SSH"
        pkt.info = (_oneline(payload, 80) if payload.startswith(b"SSH-")
                    else "Encrypted SSH packet, %d bytes" % len(payload))
        return
    if 21 in ports:
        pkt.proto = "FTP"
        pkt.info = _oneline(payload, 120)
        return
    if 23 in ports:
        pkt.proto = "TELNET"
        pkt.info = _telnet_info(payload)
        return
    if 25 in ports or 587 in ports:
        pkt.proto, pkt.info = "SMTP", _oneline(payload, 120)
        return
    if 110 in ports:
        pkt.proto, pkt.info = "POP3", _oneline(payload, 120)
        return
    if 143 in ports:
        pkt.proto, pkt.info = "IMAP", _oneline(payload, 120)
        return
    if 6667 in ports or 6697 in ports:
        pkt.proto, pkt.info = "IRC", _oneline(payload, 120)
        return
    if 6379 in ports:
        pkt.proto, pkt.info = "REDIS", _oneline(payload, 120)
        return
    if 3306 in ports:
        pkt.proto, pkt.info = "MYSQL", "MySQL protocol, %d bytes" % len(payload)
        return
    if 445 in ports or 139 in ports:
        pkt.proto = "SMB"
        if b"\xffSMB" in payload[:16]:
            pkt.info = "SMB1 message"
        elif b"\xfeSMB" in payload[:16]:
            pkt.info = "SMB2 message"
        else:
            pkt.info = "SMB data, %d bytes" % len(payload)
        return
    if 8080 in ports or 8000 in ports or 8888 in ports or 3128 in ports:
        if _is_texty(payload):
            pkt.proto = "HTTP"
            pkt.info = _oneline(payload, 120)
            return
    svc = PORT_SERVICES.get(dport) or PORT_SERVICES.get(sport)
    if svc:
        pkt.proto = svc
    if _is_texty(payload):
        pkt.info = "%s  |  %s" % (pkt.info, _oneline(payload, 90))


def _telnet_info(payload):
    if payload and payload[0] == 0xFF:
        return "Telnet negotiation (%d bytes)" % len(payload)
    txt = _oneline(payload, 90)
    return txt if txt.strip() else "Telnet data, %d bytes" % len(payload)


def _tls(pkt, payload):
    ctype = payload[0]
    names = {0x14: "Change Cipher Spec", 0x15: "Alert",
             0x16: "Handshake", 0x17: "Application Data"}
    ver = {0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2",
           0x0304: "TLS 1.3", 0x0300: "SSL 3.0"}.get(
        struct.unpack(">H", payload[1:3])[0], "TLS")
    pkt.proto = "TLS"
    info = "%s  %s" % (ver, names.get(ctype, "type %d" % ctype))
    if ctype == 0x16 and len(payload) > 5:
        hs = payload[5]
        hs_names = {1: "Client Hello", 2: "Server Hello", 11: "Certificate",
                    12: "Server Key Exchange", 14: "Server Hello Done",
                    16: "Client Key Exchange", 4: "New Session Ticket"}
        info = "%s  %s" % (ver, hs_names.get(hs, "Handshake (%d)" % hs))
        if hs == 1:
            sni = _tls_sni(payload)
            if sni:
                info += "   SNI=%s" % sni
                pkt.layers.append(Layer("TLS Client Hello",
                                        [("Server name (SNI)", sni)], 0, 0))
    pkt.info = info


def _tls_sni(p):
    try:
        i = 5 + 4 + 2 + 32                     # hs hdr, version, random
        sid = p[i]
        i += 1 + sid
        cs = struct.unpack(">H", p[i:i + 2])[0]
        i += 2 + cs
        cm = p[i]
        i += 1 + cm
        ext_len = struct.unpack(">H", p[i:i + 2])[0]
        i += 2
        end = i + ext_len
        while i + 4 <= end:
            etype, elen = struct.unpack(">HH", p[i:i + 4])
            i += 4
            if etype == 0:
                n = struct.unpack(">H", p[i + 3:i + 5])[0]
                return p[i + 5:i + 5 + n].decode("ascii", "replace")
            i += elen
    except (struct.error, IndexError):
        pass
    return ""


def _dns(pkt, payload, proto="DNS"):
    pkt.proto = proto
    try:
        tid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", payload[:12])
    except struct.error:
        pkt.info = "Malformed DNS message"
        return
    qr = flags >> 15
    opcode = (flags >> 11) & 0xF
    rcode = flags & 0xF
    off = 12
    qnames = []
    for _ in range(min(qd, 8)):
        name, off = _dns_name(payload, off)
        if off + 4 > len(payload):
            break
        qtype, _qclass = struct.unpack(">HH", payload[off:off + 4])
        off += 4
        qnames.append((name, DNS_TYPES.get(qtype, str(qtype))))
    answers = []
    for _ in range(min(an, 12)):
        if off >= len(payload):
            break
        name, off = _dns_name(payload, off)
        if off + 10 > len(payload):
            break
        rtype, _rc, _ttl, rdlen = struct.unpack(">HHIH", payload[off:off + 10])
        off += 10
        rdata = payload[off:off + rdlen]
        off += rdlen
        answers.append((name, DNS_TYPES.get(rtype, str(rtype)), _dns_rdata(rtype, rdata, payload)))

    fields = [("Transaction ID", "0x%04x" % tid),
              ("Type", "response" if qr else "query"),
              ("Opcode", str(opcode)),
              ("Questions", str(qd)), ("Answer RRs", str(an)),
              ("Authority RRs", str(ns)), ("Additional RRs", str(ar))]
    for n, t in qnames:
        fields.append(("Query", "%s  %s" % (n, t)))
    for n, t, v in answers:
        fields.append(("Answer", "%s  %s  %s" % (n, t, v)))
    if qr and rcode:
        fields.append(("Reply code", {1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
                                      4: "NOTIMP", 5: "REFUSED"}.get(rcode, str(rcode))))
    pkt.layers.append(Layer("Domain Name System", fields, 0, len(payload)))

    if qnames:
        q = "%s %s" % (qnames[0][1], qnames[0][0])
    else:
        q = "no question"
    if qr:
        ans = ", ".join(v for _, _, v in answers[:3])
        rc = {3: " [NXDOMAIN]", 2: " [SERVFAIL]", 5: " [REFUSED]"}.get(rcode, "")
        pkt.info = "Response %s%s%s" % (q, ("  →  " + ans) if ans else "", rc)
    else:
        pkt.info = "Query %s" % q
    pkt.dns_names = [n for n, _ in qnames]


def _dns_name(buf, off, depth=0):
    parts = []
    while off < len(buf) and depth < 8:
        ln = buf[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            if off + 1 >= len(buf):
                break
            ptr = ((ln & 0x3F) << 8) | buf[off + 1]
            sub, _ = _dns_name(buf, ptr, depth + 1)
            parts.append(sub)
            off += 2
            break
        parts.append(buf[off + 1:off + 1 + ln].decode("utf-8", "replace"))
        off += 1 + ln
    return ".".join(p for p in parts if p), off


def _dns_rdata(rtype, rdata, whole):
    if rtype == 1 and len(rdata) == 4:
        return ipv4(rdata)
    if rtype == 28 and len(rdata) == 16:
        return ipv6(rdata)
    if rtype in (2, 5, 12):
        return _dns_name(rdata, 0)[0] or rdata.hex()
    if rtype == 16 and rdata:
        return rdata[1:1 + rdata[0]].decode("utf-8", "replace")
    if rtype == 15 and len(rdata) > 2:
        return _dns_name(rdata, 2)[0]
    return rdata.hex()[:60]


def _dhcp(pkt, payload):
    pkt.proto = "DHCP"
    if len(payload) < 240:
        pkt.info = "BOOTP/DHCP message"
        return
    op = payload[0]
    msg_types = {1: "Discover", 2: "Offer", 3: "Request", 4: "Decline",
                 5: "ACK", 6: "NAK", 7: "Release", 8: "Inform"}
    mtype, host, req_ip = 0, "", ""
    i = 240
    while i + 2 <= len(payload):
        code, ln = payload[i], payload[i + 1]
        if code == 255:
            break
        val = payload[i + 2:i + 2 + ln]
        if code == 53 and val:
            mtype = val[0]
        elif code == 12:
            host = val.decode("utf-8", "replace")
        elif code == 50 and len(val) == 4:
            req_ip = ipv4(val)
        i += 2 + ln
    fields = [("Message type", "%s (%d)" % (msg_types.get(mtype, "?"), mtype)),
              ("Client MAC", mac(payload[28:34])),
              ("Your IP", ipv4(payload[16:20]))]
    if host:
        fields.append(("Host name", host))
    if req_ip:
        fields.append(("Requested IP", req_ip))
    pkt.layers.append(Layer("Dynamic Host Configuration Protocol", fields, 0, len(payload)))
    pkt.info = "DHCP %s%s%s" % (msg_types.get(mtype, "message" if op == 1 else "reply"),
                                ("  host=" + host) if host else "",
                                ("  req=" + req_ip) if req_ip else "")


def _tftp(pkt, payload):
    pkt.proto = "TFTP"
    if len(payload) < 2:
        return
    op = struct.unpack(">H", payload[:2])[0]
    if op in (1, 2):
        parts = payload[2:].split(b"\x00")
        fname = parts[0].decode("utf-8", "replace") if parts else ""
        pkt.info = "%s %s" % ("Read request" if op == 1 else "Write request", fname)
    elif op == 3:
        pkt.info = "Data block %d (%d bytes)" % (
            struct.unpack(">H", payload[2:4])[0], len(payload) - 4)
    elif op == 4:
        pkt.info = "Ack block %d" % struct.unpack(">H", payload[2:4])[0]
    elif op == 5:
        pkt.info = "Error: %s" % payload[4:].rstrip(b"\x00").decode("utf-8", "replace")


# ---------------------------------------------------------------------------
# text helpers
# ---------------------------------------------------------------------------

def _is_texty(b, sample=64):
    if not b:
        return False
    chunk = b[:sample]
    printable = sum(1 for c in chunk if 32 <= c < 127 or c in (9, 10, 13))
    return printable / len(chunk) > 0.85


def _oneline(b, limit=100):
    try:
        s = b.decode("utf-8", "replace")
    except Exception:
        s = repr(b)
    s = s.split("\r\n")[0].split("\n")[0]
    s = "".join(ch if ch.isprintable() else "." for ch in s).strip()
    return s[:limit] + ("…" if len(s) > limit else "")


def _header(payload, name):
    low = payload.lower()
    i = low.find(b"\r\n" + name + b":")
    if i < 0:
        return ""
    j = low.find(b"\r\n", i + 2)
    return payload[i + 2 + len(name) + 1:j].strip().decode("utf-8", "replace")
