"""Ties the pipeline together: read → dissect → conversations → carve → detect."""

from __future__ import annotations

import os
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from . import detect, reader, streams
from .dissect import dissect


@dataclass
class Stats:
    packets: int = 0
    bytes: int = 0
    duration: float = 0.0
    start: float = 0.0
    end: float = 0.0
    protocols: Counter = field(default_factory=Counter)
    proto_bytes: Counter = field(default_factory=Counter)
    talkers: Counter = field(default_factory=Counter)
    endpoints: Counter = field(default_factory=Counter)
    ports: Counter = field(default_factory=Counter)
    timeline: list = field(default_factory=list)      # (bucket_start, packets, bytes)
    avg_pps: float = 0.0
    avg_bps: float = 0.0
    ipv4: int = 0
    ipv6: int = 0
    tcp: int = 0
    udp: int = 0
    other: int = 0


class Analysis:
    """Everything the UI needs about one capture file."""

    def __init__(self, path, packets, meta, conversations, carved, findings, stats, creds):
        self.path = path
        self.name = os.path.basename(path)
        self.packets = packets
        self.meta = meta
        self.conversations = conversations
        self.carved = carved
        self.findings = findings
        self.stats = stats
        self.credentials = creds
        self.verdict = detect.verdict(findings)
        self.by_stream = {c.stream_id: c for c in conversations}


def load(path, progress=None, max_packets=0):
    """Run the whole pipeline; ``progress(fraction, message)`` drives the UI."""
    def stage(frac, msg):
        if progress:
            progress(frac, msg)

    stage(0.02, "Reading capture file…")
    raw, meta = read_with_progress(path, stage, max_packets)

    stage(0.35, "Dissecting %d packets…" % len(raw))
    packets = []
    n = max(1, len(raw))
    for i, rp in enumerate(raw):
        packets.append(dissect(rp))
        if (i & 0x7FF) == 0:
            stage(0.35 + 0.35 * i / n, "Dissecting packet %d of %d…" % (i, n))

    stage(0.72, "Rebuilding conversations…")
    convs = streams.build_conversations(packets)

    stage(0.80, "Extracting transferred files…")
    carved = streams.carve_files(convs)

    stage(0.86, "Hunting for scans and CTF patterns…")
    findings = detect.analyze(packets, convs, carved, meta)
    creds = detect.extract_credentials(packets, convs)

    stage(0.96, "Computing statistics…")
    stats = compute_stats(packets)

    stage(1.0, "Done")
    return Analysis(path, packets, meta, convs, carved, findings, stats, creds)


def read_with_progress(path, stage, max_packets):
    def cb(done, total):
        stage(0.02 + 0.30 * (done / max(1, total)), "Reading capture file…")
    return reader.read_capture(path, progress=cb, max_packets=max_packets)


def compute_stats(packets):
    st = Stats()
    if not packets:
        return st
    st.packets = len(packets)
    st.start = min(p.ts for p in packets)
    st.end = max(p.ts for p in packets)
    st.duration = max(0.0, st.end - st.start)

    for p in packets:
        size = p.wirelen or p.caplen
        st.bytes += size
        st.protocols[p.proto or "?"] += 1
        st.proto_bytes[p.proto or "?"] += size
        if p.src and p.dst:
            st.talkers[(p.src, p.dst)] += size
            st.endpoints[p.src] += size
        if p.ip_ver == 4:
            st.ipv4 += 1
        elif p.ip_ver == 6:
            st.ipv6 += 1
        t = p.transport
        if t == "TCP":
            st.tcp += 1
        elif t == "UDP":
            st.udp += 1
        else:
            st.other += 1
        if p.dport:
            st.ports[p.dport] += 1

    st.avg_pps = st.packets / st.duration if st.duration > 0 else float(st.packets)
    st.avg_bps = st.bytes * 8 / st.duration if st.duration > 0 else 0.0

    buckets = 60
    width = (st.duration / buckets) if st.duration > 0 else 1.0
    counts = [0] * buckets
    byts = [0] * buckets
    for p in packets:
        i = int((p.ts - st.start) / width) if width > 0 else 0
        i = min(buckets - 1, max(0, i))
        counts[i] += 1
        byts[i] += p.wirelen or p.caplen
    st.timeline = [(st.start + i * width, counts[i], byts[i]) for i in range(buckets)]
    return st


def protocol_tree(packets):
    """Nested protocol hierarchy counts for the overview panel."""
    tree = defaultdict(Counter)
    for p in packets:
        layer_names = [l.name for l in p.layers]
        top = p.proto or "?"
        if p.transport:
            tree[p.transport][top] += 1
        elif layer_names:
            tree[layer_names[-1]][top] += 1
    return tree
