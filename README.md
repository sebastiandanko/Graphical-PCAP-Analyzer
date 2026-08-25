# PCAP Analyzer
<img width="1612" height="994" alt="Screenshot 2026-08-25 at 22 02 50" src="https://github.com/user-attachments/assets/da057a62-6bd4-40c6-a42d-ba302a3436bc" />
A native desktop application for analysing packet captures. Load a `.pcap` /
`.pcapng` file and it tells you, in plain language, what the traffic *is* 
whether someone scanned the network, whether credentials went across in the
clear, and where the flag is hiding.

No browser, no web view, no network access, no third-party packages: pure
Python standard library + Tkinter.

```
python3 pcap-analyzer.py                      # start, then use Open capture…
python3 pcap-analyzer.py samples/recon_scan.pcap
```

## Requirements

Python 3.9+ with Tkinter.

| Platform | Install Tk |
|---|---|
| macOS (Homebrew Python) | `brew install python-tk` |
| Debian / Ubuntu | `sudo apt install python3-tk` |
| Fedora | `sudo dnf install python3-tkinter` |
| Windows | included with python.org installers |

## The window

| Tab | What it gives you |
|---|---|
| **Overview** | packets, bytes, duration, hosts, conversations at a glance; traffic-over-time chart; top protocols, talkers and ports; capture-file metadata |
| **Findings** | every detection, sorted by severity, each with a written explanation, the evidence, and jump buttons to the packets or the stream |
| **Packets** | full packet list with a filter bar, a field-by-field decode tree, and a hex dump that highlights whichever layer you select |
| **Conversations** | every TCP/UDP/ICMP/ARP flow with byte counts per direction — double-click to read it |
| **Follow Stream** | reassembled conversation, client bytes in blue, server bytes in green; ASCII / hex / one-direction views; save to disk |
| **Credentials** | usernames and passwords recovered from cleartext protocols, with how each was recovered |
| **Files** | files carved out of HTTP bodies and raw streams, with preview and export |

A verdict banner across the top states the headline result — `SCAN DETECTED`,
`MALICIOUS / SENSITIVE CONTENT`, `SUSPICIOUS ACTIVITY` or `CLEAN` — before you
open a single tab.
<img width="1612" height="994" alt="Screenshot 2026-08-25 at 22 02 31" src="https://github.com/user-attachments/assets/e9fd4204-2fe0-41bf-a7b4-465d2dbd905a" />
### Readability

* WCAG-AA contrast throughout, verified numerically: every text/background pair
  is ≥ 4.9:1 in both the dark and the light theme.
* `Cmd +` / `Cmd -` scales every font in the app (charts and tables included);
  `Cmd L` switches light/dark.
* Severity and protocol are shown by colour **and** by text, never colour alone.
* Zebra-striped, click-to-sort tables with 27 px rows; monospace for anything
  byte-aligned, proportional for prose.
* Long analyses run on a worker thread behind a progress bar, so the window
  never freezes.

## What the scanner looks for

**Reconnaissance** — TCP SYN / connect / NULL / FIN / XMAS scans (with the
technique named and open ports listed), UDP scans, horizontal sweeps, ARP
scans, ICMP ping sweeps, traceroute, DNS zone transfers, directory brute
forcing.

**Credentials and secrets** — FTP, Telnet (reconstructed from keystrokes),
HTTP Basic / Bearer / form posts, POP3, IMAP, SMTP `AUTH LOGIN`/`PLAIN`,
Redis `AUTH`, SNMP communities, PEM private keys, AWS access keys, JWTs.

**CTF patterns** — `flag{…}`-style tokens found in cleartext, base64, hex,
ROT13 and single-byte XOR (brute-forced over all 255 keys); DNS tunnelling
(entropy + cardinality scored, and the exfiltrated data reassembled and
decoded); ICMP tunnelling; files carved from HTTP/FTP/raw TCP; remote shell
sessions; C2 beaconing detected by interval jitter; SQL injection, path
traversal / LFI, command injection, XSS, web shells and scanner user agents;
brute-force login attempts; suspicious ports; large one-way uploads.

## Filter syntax (Packets tab)

Tokens are combined with AND:

```
tcp udp icmp arp dns http tls ftp telnet ssh …   protocol
port 80 · sport 1234 · dport 53                  ports
ip 10.0.0.5 · src 10.0.0.5 · dst 8.8.8.8         addresses
contains password                                substring in payload or info
syn ack rst fin psh urg                          TCP flags
flag                                             packets containing a flag pattern
payload                                          packets carrying application data
anything else                                    free text across all columns
```

Example: `tcp port 21 contains PASS`

## Sample captures

`tools/make_samples.py` builds two demo files from scratch (no capture
hardware needed):

* **`samples/recon_scan.pcap`** — an ARP sweep, an ICMP sweep, a 385-port
  nmap-style SYN scan with three open ports, NULL-scan probes and a UDP scan.
* **`samples/ctf_challenge.pcap`** — cleartext FTP/Telnet/SMTP logins, an HTTP
  Basic header, six flags hidden six different ways, a PNG and an RSA private
  key transferred over the wire, DNS exfiltration of a customer table, an ICMP
  tunnel, a Windows reverse shell on port 4444, C2 beaconing and web-attack
  traffic.

```
python3 tools/make_samples.py      # regenerate
python3 tools/smoke_test.py        # 127 UI checks across both samples
```

## Reports

**File → Export report** writes a Markdown report: verdict, capture metadata,
every finding with its detail and packet numbers, the credential table, the
extracted-object list, top conversations and the protocol breakdown.

## Layout

```
pcap-analyzer.py        launcher
pcapx/reader.py         libpcap + pcapng parsing (both endiannesses, ns timestamps)
pcapx/dissect.py        Ethernet/VLAN/SLL · IPv4/IPv6 · TCP/UDP/ICMP/ARP ·
                        HTTP, DNS, TLS (incl. SNI), DHCP, FTP, SMTP, TFTP, SMB…
pcapx/streams.py        conversation tracking, TCP reassembly, file carving
pcapx/detect.py         scan detection + CTF pattern hunting
pcapx/session.py        pipeline and statistics
pcapx/theme.py          palette, fonts, ttk styling
pcapx/widgets.py        tables, hex view, charts, banner
pcapx/app.py            main window and tabs
```

## Limitations

Packet-list rendering is capped at 20,000 rows at a time (narrow the filter to
see more); TCP reassembly does not reorder across sequence-number wraparound;
IP fragments are shown but not reassembled; encrypted traffic is characterised
by its shape only, never decrypted.
