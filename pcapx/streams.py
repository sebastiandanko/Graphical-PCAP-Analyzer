"""Conversation tracking, TCP stream reassembly and file carving."""

from __future__ import annotations

import gzip
import hashlib
import zlib
from dataclasses import dataclass, field

from .dissect import PORT_SERVICES


@dataclass
class Conversation:
    key: tuple
    stream_id: int
    proto: str                       # TCP / UDP / ICMP / ARP / other
    a_ip: str = ""
    a_port: int = 0
    b_ip: str = ""
    b_port: int = 0
    packets: list = field(default_factory=list)      # packet indices, chronological
    pkts_ab: int = 0
    pkts_ba: int = 0
    bytes_ab: int = 0
    bytes_ba: int = 0
    start: float = 0.0
    end: float = 0.0
    flags_seen: int = 0
    service: str = ""
    # reassembly buffers: list[(ts, packet_index, direction, seq, payload)]
    segments: list = field(default_factory=list)

    @property
    def duration(self):
        return max(0.0, self.end - self.start)

    @property
    def total_bytes(self):
        return self.bytes_ab + self.bytes_ba

    @property
    def total_packets(self):
        return self.pkts_ab + self.pkts_ba

    def label(self):
        if self.proto in ("TCP", "UDP"):
            return "%s:%d ↔ %s:%d" % (self.a_ip, self.a_port, self.b_ip, self.b_port)
        return "%s ↔ %s" % (self.a_ip, self.b_ip)

    # -- reassembly ---------------------------------------------------------

    def _reassemble(self, direction):
        segs = [s for s in self.segments if s[2] == direction and s[4]]
        if not segs:
            return b""
        if self.proto != "TCP":
            return b"".join(s[4] for s in segs)
        segs.sort(key=lambda s: (s[3], s[0]))
        out = bytearray()
        next_seq = None
        for _ts, _idx, _d, seq, data in segs:
            if next_seq is None:
                next_seq = seq
            if seq == next_seq:
                out += data
                next_seq = seq + len(data)
            elif seq > next_seq:
                out += data                       # gap (missing segment); keep going
                next_seq = seq + len(data)
            else:
                overlap = next_seq - seq
                if overlap < len(data):
                    out += data[overlap:]
                    next_seq = seq + len(data)
        return bytes(out)

    def data_ab(self):
        return self._reassemble(0)

    def data_ba(self):
        return self._reassemble(1)

    def chunks(self):
        """Chronological (direction, bytes) chunks for the follow-stream view."""
        merged = []
        for ts, idx, d, _seq, data in sorted(self.segments, key=lambda s: (s[0], s[1])):
            if not data:
                continue
            if merged and merged[-1][0] == d:
                merged[-1][1].extend(data)
            else:
                merged.append((d, bytearray(data), idx))
        return [(d, bytes(buf), idx) for d, buf, idx in merged]


def build_conversations(packets):
    """Group dissected packets into bidirectional conversations."""
    convs = {}
    order = 0
    for pkt in packets:
        if not pkt.src:
            continue
        proto = pkt.transport or pkt.proto
        if proto not in ("TCP", "UDP", "ICMP", "ICMPv6", "ARP"):
            proto = proto or "OTHER"
        if proto in ("TCP", "UDP"):
            fwd = (pkt.src, pkt.sport, pkt.dst, pkt.dport)
            rev = (pkt.dst, pkt.dport, pkt.src, pkt.sport)
        else:
            fwd = (pkt.src, 0, pkt.dst, 0)
            rev = (pkt.dst, 0, pkt.src, 0)
        kf, kr = (proto,) + fwd, (proto,) + rev
        if kr in convs:
            conv, direction = convs[kr], 1
        elif kf in convs:
            conv, direction = convs[kf], 0
        else:
            conv = Conversation(key=kf, stream_id=order, proto=proto,
                                a_ip=fwd[0], a_port=fwd[1], b_ip=fwd[2], b_port=fwd[3],
                                start=pkt.ts, end=pkt.ts)
            conv.service = (PORT_SERVICES.get(pkt.dport) or PORT_SERVICES.get(pkt.sport) or "")
            convs[kf] = conv
            order += 1
            direction = 0

        conv.packets.append(pkt.index)
        conv.end = max(conv.end, pkt.ts)
        conv.start = min(conv.start, pkt.ts)
        conv.flags_seen |= pkt.tcp_flags
        size = pkt.wirelen or pkt.caplen
        if direction == 0:
            conv.pkts_ab += 1
            conv.bytes_ab += size
        else:
            conv.pkts_ba += 1
            conv.bytes_ba += size
        pkt.stream_key = conv.key
        if pkt.payload:
            conv.segments.append((pkt.ts, pkt.index, direction, pkt.seq, pkt.payload))
    return list(convs.values())


# ---------------------------------------------------------------------------
# file carving
# ---------------------------------------------------------------------------

FILE_SIGNATURES = [
    (b"\x89PNG\r\n\x1a\n", "png", "PNG image"),
    (b"\xff\xd8\xff", "jpg", "JPEG image"),
    (b"GIF87a", "gif", "GIF image"),
    (b"GIF89a", "gif", "GIF image"),
    (b"BM", "bmp", "BMP image"),
    (b"%PDF-", "pdf", "PDF document"),
    (b"PK\x03\x04", "zip", "ZIP archive (or docx/xlsx/jar/apk)"),
    (b"Rar!\x1a\x07", "rar", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7z", "7-Zip archive"),
    (b"\x1f\x8b\x08", "gz", "gzip stream"),
    (b"BZh", "bz2", "bzip2 archive"),
    (b"\xfd7zXZ", "xz", "XZ archive"),
    (b"\x7fELF", "elf", "ELF executable"),
    (b"MZ", "exe", "DOS/PE executable"),
    (b"\xca\xfe\xba\xbe", "class", "Java class / Mach-O fat binary"),
    (b"\xcf\xfa\xed\xfe", "macho", "Mach-O executable"),
    (b"OggS", "ogg", "Ogg media"),
    (b"ID3", "mp3", "MP3 audio"),
    (b"RIFF", "riff", "RIFF container (WAV/AVI)"),
    (b"\x00\x00\x00\x18ftyp", "mp4", "MP4 video"),
    (b"SQLite format 3\x00", "sqlite", "SQLite database"),
    (b"-----BEGIN ", "pem", "PEM key/certificate"),
    (b"\x1f\x9d", "Z", "compress'd data"),
]

MIN_CARVE = 24


@dataclass
class CarvedFile:
    name: str
    kind: str
    ext: str
    size: int
    data: bytes
    source: str
    stream_id: int
    packet: int


def carve_files(conversations, limit=200):
    """Pull recognisable files out of reassembled streams (HTTP-aware).

    The same bytes often show up twice — once as an HTTP body and once via a raw
    magic-byte match — so results are de-duplicated on content.
    """
    out = []
    for conv in conversations:
        if conv.proto not in ("TCP", "UDP"):
            continue
        for direction, blob in ((0, conv.data_ab()), (1, conv.data_ba())):
            if not blob or len(blob) < MIN_CARVE:
                continue
            first_pkt = conv.packets[0] if conv.packets else 0
            src = "%s → %s" % ((conv.label().split(" ↔ ")[0], conv.label().split(" ↔ ")[-1])
                               if direction == 0 else
                               (conv.label().split(" ↔ ")[-1], conv.label().split(" ↔ ")[0]))
            out.extend(_carve_http(blob, conv, src, first_pkt))
            out.extend(_carve_magic(blob, conv, src, first_pkt))
            if len(out) >= limit * 2:
                break
    return _dedupe_files(out)[:limit]


def _dedupe_files(files):
    """Keep one entry per distinct payload, preferring the HTTP-named copy."""
    best = {}
    order = []
    for f in files:
        digest = hashlib.sha1(f.data).digest()
        prev = best.get(digest)
        if prev is None:
            best[digest] = f
            order.append(digest)
        elif "HTTP" in f.source and "HTTP" not in prev.source:
            best[digest] = f
    return [best[d] for d in order]


def _carve_http(blob, conv, src, pkt_no):
    files = []
    pos = 0
    while True:
        i = blob.find(b"HTTP/1.", pos)
        if i < 0:
            break
        hdr_end = blob.find(b"\r\n\r\n", i)
        if hdr_end < 0:
            break
        headers = blob[i:hdr_end].decode("latin-1", "replace")
        body_start = hdr_end + 4
        low = headers.lower()
        clen = _hdr_int(low, "content-length")
        chunked = "transfer-encoding:" in low and "chunked" in low
        if chunked:
            body, nxt = _dechunk(blob, body_start)
        elif clen is not None:
            body, nxt = blob[body_start:body_start + clen], body_start + clen
        else:
            body, nxt = blob[body_start:], len(blob)
        pos = max(nxt, i + 1)
        if len(body) < 64:                      # error pages / tiny control bodies
            continue
        if "content-encoding:" in low and "gzip" in low:
            body = _try_gunzip(body)
        elif "content-encoding:" in low and "deflate" in low:
            try:
                body = zlib.decompress(body)
            except zlib.error:
                pass
        ctype = _hdr_str(headers, "content-type") or "application/octet-stream"
        name = _http_name(headers, ctype)
        kind = _describe(body, ctype)
        files.append(CarvedFile(name, kind, name.rsplit(".", 1)[-1], len(body),
                                body, src + "  (HTTP body)", conv.stream_id, pkt_no))
        if len(files) > 40:
            break
    return files


def _carve_magic(blob, conv, src, pkt_no):
    files = []
    for sig, ext, kind in FILE_SIGNATURES:
        if ext in ("exe", "riff", "bmp") and len(sig) <= 2:
            continue                                    # too short: skip loose matches
        start = 0
        found = 0
        while found < 4:
            i = blob.find(sig, start)
            if i < 0:
                break
            start = i + len(sig)
            found += 1
            data = blob[i:]
            if ext == "png":
                end = data.find(b"IEND\xaeB`\x82")
                if end > 0:
                    data = data[:end + 8]
            elif ext in ("jpg",):
                end = data.find(b"\xff\xd9")
                if end > 0:
                    data = data[:end + 2]
            elif ext == "gif":
                end = data.rfind(b"\x00\x3b")
                if end > 0:
                    data = data[:end + 2]
            elif ext == "pem":
                end = data.find(b"-----END ")
                if end > 0:
                    e2 = data.find(b"-----", end + 9)
                    data = data[:e2 + 5 if e2 > 0 else end + 40]
            if len(data) < MIN_CARVE:
                continue
            files.append(CarvedFile(
                "stream%d_%d.%s" % (conv.stream_id, i, ext), kind, ext,
                len(data), data, src + "  (raw stream)", conv.stream_id, pkt_no))
    return files


def _try_gunzip(body):
    try:
        return gzip.decompress(body)
    except (OSError, EOFError, zlib.error):
        return body


def _dechunk(blob, pos):
    out = bytearray()
    while pos < len(blob):
        nl = blob.find(b"\r\n", pos)
        if nl < 0:
            break
        try:
            size = int(blob[pos:nl].split(b";")[0].strip(), 16)
        except ValueError:
            break
        pos = nl + 2
        if size == 0:
            pos += 2
            break
        out += blob[pos:pos + size]
        pos += size + 2
    return bytes(out), pos


def _hdr_int(low_headers, name):
    for line in low_headers.split("\r\n"):
        if line.startswith(name + ":"):
            try:
                return int(line.split(":", 1)[1].strip())
            except ValueError:
                return None
    return None


def _hdr_str(headers, name):
    for line in headers.split("\r\n"):
        if line.lower().startswith(name + ":"):
            return line.split(":", 1)[1].strip()
    return ""


EXT_BY_CTYPE = {
    "image/png": "png", "image/jpeg": "jpg", "image/gif": "gif",
    "application/zip": "zip", "application/pdf": "pdf", "text/html": "html",
    "text/plain": "txt", "application/json": "json", "text/css": "css",
    "application/javascript": "js", "application/octet-stream": "bin",
    "application/x-gzip": "gz", "audio/wav": "wav", "image/x-icon": "ico",
}


def _http_name(headers, ctype):
    disp = _hdr_str(headers, "content-disposition")
    if "filename=" in disp:
        return disp.split("filename=", 1)[1].strip('"; ').replace("/", "_")[:60] or "download"
    base = ctype.split(";")[0].strip().lower()
    return "object.%s" % EXT_BY_CTYPE.get(base, base.split("/")[-1][:8] or "bin")


def _describe(body, ctype):
    for sig, _ext, kind in FILE_SIGNATURES:
        if body.startswith(sig):
            return kind
    return ctype.split(";")[0]
