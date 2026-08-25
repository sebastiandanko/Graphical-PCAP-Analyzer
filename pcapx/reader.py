"""Capture file readers: classic libpcap (.pcap) and pcapng (.pcapng).

No third-party dependencies -- everything is parsed from raw bytes so the
application runs on a stock Python install.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

PCAP_MAGIC_BE = 0xA1B2C3D4          # seconds / microseconds
PCAP_MAGIC_LE = 0xD4C3B2A1
PCAP_NSEC_MAGIC_BE = 0xA1B23C4D     # seconds / nanoseconds
PCAP_NSEC_MAGIC_LE = 0x4DC3B2A1
PCAPNG_SHB = 0x0A0D0D0A


class CaptureError(Exception):
    """Raised when a file is not a capture we can understand."""


@dataclass(slots=True)
class RawPacket:
    index: int
    ts: float          # epoch seconds, fractional
    caplen: int        # bytes actually stored
    wirelen: int       # bytes on the wire
    data: bytes
    linktype: int


def read_capture(path, progress=None, max_packets=0):
    """Read *path* and return ``(packets, meta)``.

    ``progress`` is an optional ``callable(bytes_done, bytes_total)`` used to
    drive the loading bar; ``max_packets`` caps the number of packets read.
    """
    with open(path, "rb") as fh:
        blob = fh.read()
    if len(blob) < 4:
        raise CaptureError("File is too small to be a capture file.")

    magic = struct.unpack(">I", blob[:4])[0]
    if magic == PCAPNG_SHB:
        return _read_pcapng(blob, progress, max_packets)
    if magic in (PCAP_MAGIC_BE, PCAP_MAGIC_LE, PCAP_NSEC_MAGIC_BE, PCAP_NSEC_MAGIC_LE):
        return _read_pcap(blob, magic, progress, max_packets)
    raise CaptureError(
        "Unrecognised file format (magic 0x%08x).\n"
        "Supported: libpcap (.pcap / .cap) and pcapng (.pcapng)." % magic
    )


# --------------------------------------------------------------------------
# classic libpcap
# --------------------------------------------------------------------------

def _read_pcap(blob, magic, progress, max_packets):
    endian = "<" if magic in (PCAP_MAGIC_LE, PCAP_NSEC_MAGIC_LE) else ">"
    nano = magic in (PCAP_NSEC_MAGIC_BE, PCAP_NSEC_MAGIC_LE)
    if len(blob) < 24:
        raise CaptureError("Truncated pcap header.")

    vmaj, vmin, _tz, _sig, snaplen, linktype = struct.unpack(endian + "HHiIII", blob[4:24])
    divisor = 1e9 if nano else 1e6
    packets = []
    off = 24
    total = len(blob)
    idx = 0
    truncated = False

    while off + 16 <= total:
        ts_sec, ts_frac, caplen, wirelen = struct.unpack(endian + "IIII", blob[off:off + 16])
        off += 16
        if caplen > total - off:
            truncated = True
            caplen = total - off
        data = blob[off:off + caplen]
        off += caplen
        packets.append(RawPacket(idx, ts_sec + ts_frac / divisor, caplen, wirelen,
                                 data, linktype & 0xFFFF))
        idx += 1
        if progress and (idx & 0x3FF) == 0:
            progress(off, total)
        if max_packets and idx >= max_packets:
            break

    meta = {
        "format": "libpcap",
        "version": "%d.%d" % (vmaj, vmin),
        "endian": "little" if endian == "<" else "big",
        "resolution": "nanosecond" if nano else "microsecond",
        "snaplen": snaplen,
        "linktypes": {linktype & 0xFFFF},
        "truncated": truncated,
        "filesize": total,
    }
    if progress:
        progress(total, total)
    return packets, meta


# --------------------------------------------------------------------------
# pcapng
# --------------------------------------------------------------------------

def _read_pcapng(blob, progress, max_packets):
    packets = []
    interfaces = []           # (linktype, snaplen, ts_divisor)
    off = 0
    total = len(blob)
    endian = "<"
    idx = 0
    truncated = False
    versions = set()

    while off + 12 <= total:
        btype = struct.unpack(endian + "I", blob[off:off + 4])[0]
        if btype == PCAPNG_SHB or (off == 0):
            # Section header: (re)establish endianness from the byte-order magic.
            bom = blob[off + 8:off + 12]
            if bom == b"\x1a\x2b\x3c\x4d":
                endian = "<"
            elif bom == b"\x4d\x3c\x2b\x1a":
                endian = ">"
            else:
                raise CaptureError("pcapng section header has a bad byte-order magic.")
            btype = struct.unpack(endian + "I", blob[off:off + 4])[0]
            if btype != PCAPNG_SHB:
                raise CaptureError("Expected a pcapng section header block.")
            interfaces = []

        blen = struct.unpack(endian + "I", blob[off + 4:off + 8])[0]
        if blen < 12 or off + blen > total:
            truncated = True
            break
        body = blob[off + 8:off + blen - 4]

        if btype == PCAPNG_SHB:
            vmaj, vmin = struct.unpack(endian + "HH", body[4:8])
            versions.add("%d.%d" % (vmaj, vmin))
        elif btype == 0x00000001:                       # Interface Description
            linktype, _res, snaplen = struct.unpack(endian + "HHI", body[:8])
            divisor = _if_tsresol(body[8:], endian)
            interfaces.append((linktype, snaplen, divisor))
        elif btype == 0x00000006:                       # Enhanced Packet Block
            if_id, ts_hi, ts_lo, caplen, wirelen = struct.unpack(endian + "IIIII", body[:20])
            linktype, _snap, divisor = _iface(interfaces, if_id)
            data = body[20:20 + caplen]
            ts = ((ts_hi << 32) | ts_lo) / divisor
            packets.append(RawPacket(idx, ts, len(data), wirelen, data, linktype))
            idx += 1
        elif btype == 0x00000003:                       # Simple Packet Block
            wirelen = struct.unpack(endian + "I", body[:4])[0]
            linktype, snaplen, _div = _iface(interfaces, 0)
            caplen = min(wirelen, snaplen or wirelen, len(body) - 4)
            data = body[4:4 + caplen]
            packets.append(RawPacket(idx, 0.0, len(data), wirelen, data, linktype))
            idx += 1

        off += blen
        if progress and (idx & 0x3FF) == 0:
            progress(off, total)
        if max_packets and idx >= max_packets:
            break

    if not packets and not interfaces:
        raise CaptureError("pcapng file contains no packets.")

    meta = {
        "format": "pcapng",
        "version": ", ".join(sorted(versions)) or "1.0",
        "endian": "little" if endian == "<" else "big",
        "resolution": "per-interface",
        "snaplen": interfaces[0][1] if interfaces else 0,
        "linktypes": {i[0] for i in interfaces} or {1},
        "truncated": truncated,
        "filesize": total,
    }
    if progress:
        progress(total, total)
    return packets, meta


def _iface(interfaces, if_id):
    if if_id < len(interfaces):
        return interfaces[if_id]
    return (1, 0, 1e6)


def _if_tsresol(opts, endian):
    """Walk IDB options looking for if_tsresol (code 9); default is 1e6."""
    off = 0
    while off + 4 <= len(opts):
        code, length = struct.unpack(endian + "HH", opts[off:off + 4])
        off += 4
        val = opts[off:off + length]
        off += (length + 3) & ~3
        if code == 0:
            break
        if code == 9 and val:
            raw = val[0]
            if raw & 0x80:
                return float(2 ** (raw & 0x7F))
            return float(10 ** raw)
    return 1e6


LINKTYPE_NAMES = {
    0: "NULL/Loopback",
    1: "Ethernet",
    9: "PPP",
    12: "Raw IP",
    101: "Raw IP",
    105: "IEEE 802.11",
    113: "Linux cooked (SLL)",
    127: "802.11 Radiotap",
    228: "Raw IPv4",
    229: "Raw IPv6",
    276: "Linux cooked v2 (SLL2)",
}


def linktype_name(lt):
    return LINKTYPE_NAMES.get(lt, "Linktype %d" % lt)
