# Network Analyser

A Python script that uses scapy to read a `.pcap` file (a packet capture from Wireshark or tcpdump). It summarises the traffic and flags a couple of suspicious patterns.

It only reads saved capture files. **It does not sniff live traffic.**

**Only use this on networks you own or have permission to analyse.** Capturing other people's traffic without permission is illegal.

## What it does

- **Top talkers**: which IPs sent the most data.
- **Protocol breakdown**: TCP / UDP / ICMP / DNS / HTTP / HTTPS.
- **Most used destination ports**.
- **DNS queries**: which domain names were looked up.
- **Alerts**:
  - *Possible port scan*: one IP sending connection attempts (SYN packets) to 15+ different ports within 10 seconds.
  - *Unusual ports*: traffic to ports that aren't on my list of common ones (e.g. 4444, which is the default port for a lot of reverse shells).

## Why I built it

After learning about TCP/IP and ports at school, I started using Wireshark. I wanted to understand what's actually inside a capture and try to spot something like an nmap scan with my own code instead of just clicking through Wireshark.

## How to run it

```
pip install -r requirements.txt
python network_analyser.py sample.pcap
python network_analyser.py sample.pcap -o report.txt
```

`sample.pcap` is a **fake** capture made by `make_sample.py` with scapy. It only uses documentation-range IPs (192.0.2.x, 198.51.100.x, 203.0.113.x) and made-up MAC addresses. It includes some normal browsing, DNS, a ping, a fake port scan and a connection to port 4444. You can regenerate it with `python make_sample.py`.

On Windows, scapy might show a warning about Npcap. That's fine for reading pcap files. Npcap is only needed for live capture.

## Capturing your own traffic

Only do this on your own network or devices.

- **Wireshark**: pick your network interface, click start, browse a bit, click stop, then File > Save As and choose `.pcap`.
- **tcpdump** (Linux/Mac):
  ```
  sudo tcpdump -i eth0 -c 1000 -w my_capture.pcap
  ```
  `-c 1000` stops after 1000 packets. Change `eth0` to your interface (`ip a` shows them).

Real captures contain your IPs, MAC addresses and device names, so **don't upload them to GitHub**. The `.gitignore` blocks every `.pcap` except the sample.

## Example output

```
==================================================
NETWORK REPORT for sample.pcap
==================================================
Total packets: 98

Top talkers (by bytes sent):
  198.51.100.20     22.6 KB
  192.0.2.10        4.0 KB
  192.0.2.11        1.3 KB
  203.0.113.66      1.1 KB
  198.51.100.30     654 B

Protocols:
  HTTPS             57
  TCP               22
  DNS               8
  ICMP              6
  HTTP              5

Most used destination ports:
  443               29
  53                5
  4444              5
  80                3
  21                1

DNS queries seen:
  example.com                   2
  example.org                   1
  example.net                   1

ALERTS (2)
--------------------------------------------------
[!] 203.0.113.66 tried 20 different ports on 192.0.2.10 in under 10s (possible port scan)
[!] traffic to unusual port 4444 (5 packets)
```

## What I learned

- How packets are built in layers (Ethernet > IP > TCP/UDP > data) and how scapy lets you pull each layer out.
- TCP flags. At first I counted every packet for the port scan check, and normal replies made everything look like a scan. Only counting SYN packets (new connections) fixed that.
- Replies come back on random high ports (49152+), so I skip those in the port counts.
- A fixed list of "common ports" is a very rough way to find unusual traffic and will give false positives on a real network.

## TODO

- Track unusual ports per IP properly instead of the hack I've got.
- Flag lots of DNS queries to random looking domains (could be DNS tunnelling).
- Maybe a live mode, but only with a flag so it's never on by default.
