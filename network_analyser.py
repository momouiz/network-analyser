# network analyser
# reads a .pcap file (saved from wireshark or tcpdump) and shows a summary
# of the traffic, plus flags a couple of simple suspicious things
# usage: python network_analyser.py sample.pcap

import argparse
from collections import Counter, defaultdict

from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS, DNSQR

# settings
SCAN_PORT_LIMIT = 15     # one ip hitting this many different ports...
SCAN_SECONDS = 10        # ...within this many seconds = possible port scan
TOP_N = 5

# ports i would expect to see on a normal network
# anything else gets flagged as "unusual" (this list is very basic)
COMMON_PORTS = {20, 21, 22, 25, 53, 67, 68, 80, 110, 123, 143, 443, 445, 465, 587, 993, 995, 3389, 5353}


def get_protocol(pkt):
    # work out the main protocol of a packet
    if pkt.haslayer(DNS):
        return "DNS"
    if pkt.haslayer(TCP):
        if pkt[TCP].dport in (80, 8080) or pkt[TCP].sport in (80, 8080):
            return "HTTP"
        if pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
            return "HTTPS"
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    return "Other"


def analyse(packets):
    talkers = Counter()        # source ip -> bytes sent
    protocols = Counter()
    dest_ports = Counter()
    dns_queries = Counter()
    port_hits = defaultdict(list)   # source ip -> list of (time, dest ip, port)

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        src = pkt[IP].src
        talkers[src] += len(pkt)
        protocols[get_protocol(pkt)] += 1

        dport = None
        if pkt.haslayer(TCP):
            dport = pkt[TCP].dport
            # only count SYN packets (new connections) for the scan check
            # otherwise normal replies would look like a scan
            if pkt[TCP].flags & 0x02 and not pkt[TCP].flags & 0x10:
                port_hits[src].append((float(pkt.time), pkt[IP].dst, dport))
        elif pkt.haslayer(UDP):
            dport = pkt[UDP].dport
        if dport is not None and dport < 49152:
            # ports above 49152 are usually just the random reply ports so skip them
            dest_ports[dport] += 1

        # qr == 0 means it's a question not an answer
        if pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
            name = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            dns_queries[name] += 1

    return talkers, protocols, dest_ports, dns_queries, port_hits


def find_port_scans(port_hits):
    alerts = []
    for src in port_hits:
        hits = sorted(port_hits[src])
        # sliding window over the connection attempts
        for i in range(len(hits)):
            ports = set()
            target = hits[i][1]
            for j in range(i, len(hits)):
                if hits[j][0] - hits[i][0] > SCAN_SECONDS:
                    break
                ports.add(hits[j][2])
            if len(ports) >= SCAN_PORT_LIMIT:
                alerts.append(src + " tried " + str(len(ports)) + " different ports on " + target +
                              " in under " + str(SCAN_SECONDS) + "s (possible port scan)")
                break   # one alert per ip is enough
    return alerts


def find_unusual_ports(dest_ports, scanners):
    alerts = []
    for port, count in dest_ports.most_common():
        if port not in COMMON_PORTS:
            alerts.append("traffic to unusual port " + str(port) + " (" + str(count) + " packets)")
    return alerts


def human_bytes(n):
    if n < 1024:
        return str(n) + " B"
    return str(round(n / 1024, 1)) + " KB"


def main():
    parser = argparse.ArgumentParser(description="Summarise a .pcap file and flag suspicious traffic")
    parser.add_argument("pcap", help="the .pcap file to read")
    parser.add_argument("-o", "--output", help="save the report to a text file")
    args = parser.parse_args()

    print("Reading " + args.pcap + " ...")
    packets = rdpcap(args.pcap)
    talkers, protocols, dest_ports, dns_queries, port_hits = analyse(packets)

    lines = []
    lines.append("=" * 50)
    lines.append("NETWORK REPORT for " + args.pcap)
    lines.append("=" * 50)
    lines.append("Total packets: " + str(len(packets)))
    lines.append("")

    lines.append("Top talkers (by bytes sent):")
    for ip, b in talkers.most_common(TOP_N):
        lines.append("  " + ip.ljust(18) + human_bytes(b))
    lines.append("")

    lines.append("Protocols:")
    for proto, c in protocols.most_common():
        lines.append("  " + proto.ljust(18) + str(c))
    lines.append("")

    lines.append("Most used destination ports:")
    for port, c in dest_ports.most_common(TOP_N):
        lines.append("  " + str(port).ljust(18) + str(c))
    lines.append("")

    lines.append("DNS queries seen:")
    if len(dns_queries) == 0:
        lines.append("  none")
    for name, c in dns_queries.most_common(10):
        lines.append("  " + name.ljust(30) + str(c))
    lines.append("")

    scans = find_port_scans(port_hits)
    # if an ip is port scanning, every port it hits looks "unusual"
    # so i only check unusual ports for traffic that isnt from a scanner
    # TODO: this is a bit of a hack, should probably track it per ip
    scanner_ips = [s.split(" ")[0] for s in scans]
    if scanner_ips:
        clean = Counter()
        for pkt in packets:
            if pkt.haslayer(IP) and pkt[IP].src not in scanner_ips and (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
                layer = pkt[TCP] if pkt.haslayer(TCP) else pkt[UDP]
                if layer.dport < 49152:
                    clean[layer.dport] += 1
        unusual = find_unusual_ports(clean, scanner_ips)
    else:
        unusual = find_unusual_ports(dest_ports, scanner_ips)

    alerts = scans + unusual
    lines.append("ALERTS (" + str(len(alerts)) + ")")
    lines.append("-" * 50)
    if len(alerts) == 0:
        lines.append("nothing suspicious found")
    for a in alerts:
        lines.append("[!] " + a)

    report = "\n".join(lines)
    print(report)

    if args.output:
        f = open(args.output, "w")
        f.write(report + "\n")
        f.close()
        print("\nReport saved to " + args.output)


if __name__ == "__main__":
    main()
