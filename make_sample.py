# makes a small FAKE sample.pcap so the analyser can be tested
# all ips are from the documentation ranges so none of them are real
# usage: python make_sample.py

import random
from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Ether, Raw, wrpcap

random.seed(1)
packets = []
t = 1700000000.0

# made up mac addresses (locally administered, not real devices)
MAC_A = "02:00:00:00:00:01"
MAC_B = "02:00:00:00:00:02"


def add(pkt, gap=0.05):
    global t
    t += gap
    pkt.time = t
    packets.append(pkt)


laptop = "192.0.2.10"
phone = "192.0.2.11"
dns_server = "192.0.2.1"
web1 = "198.51.100.20"
web2 = "198.51.100.30"
scanner = "203.0.113.66"

# normal browsing: dns lookup then https
for host, name in [(laptop, "example.com"), (phone, "example.org"), (laptop, "example.net"), (laptop, "example.com")]:
    sport = random.randint(50000, 60000)
    add(Ether(src=MAC_A, dst=MAC_B) / IP(src=host, dst=dns_server) / UDP(sport=sport, dport=53) / DNS(rd=1, qd=DNSQR(qname=name)))
    add(Ether(src=MAC_B, dst=MAC_A) / IP(src=dns_server, dst=host) / UDP(sport=53, dport=sport) /
        DNS(qr=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, rdata=web1)))
    sport = random.randint(50000, 60000)
    add(Ether(src=MAC_A, dst=MAC_B) / IP(src=host, dst=web1) / TCP(sport=sport, dport=443, flags="S"))
    add(Ether(src=MAC_B, dst=MAC_A) / IP(src=web1, dst=host) / TCP(sport=443, dport=sport, flags="SA"))
    for i in range(6):
        add(Ether(src=MAC_A, dst=MAC_B) / IP(src=host, dst=web1) / TCP(sport=sport, dport=443, flags="PA") / Raw(b"x" * 120))
        add(Ether(src=MAC_B, dst=MAC_A) / IP(src=web1, dst=host) / TCP(sport=443, dport=sport, flags="PA") / Raw(b"y" * 900))

# a bit of plain http
sport = 51515
add(Ether(src=MAC_A, dst=MAC_B) / IP(src=phone, dst=web2) / TCP(sport=sport, dport=80, flags="S"))
add(Ether(src=MAC_A, dst=MAC_B) / IP(src=phone, dst=web2) / TCP(sport=sport, dport=80, flags="PA") / Raw(b"GET / HTTP/1.1\r\nHost: example.org\r\n\r\n"))
add(Ether(src=MAC_B, dst=MAC_A) / IP(src=web2, dst=phone) / TCP(sport=80, dport=sport, flags="PA") / Raw(b"z" * 600))

# ping
for i in range(3):
    add(Ether(src=MAC_A, dst=MAC_B) / IP(src=laptop, dst=dns_server) / ICMP(), gap=1)
    add(Ether(src=MAC_B, dst=MAC_A) / IP(src=dns_server, dst=laptop) / ICMP(type=0))

# port scan: one ip sends SYNs to lots of ports on the laptop very quickly
for port in [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 1433, 3306, 3389, 5900, 8080, 8443, 9000]:
    add(Ether(src=MAC_B, dst=MAC_A) / IP(src=scanner, dst=laptop) / TCP(sport=40000, dport=port, flags="S"), gap=0.02)

# connection to an unusual port (could be a backdoor / something odd)
sport = 52222
add(Ether(src=MAC_A, dst=MAC_B) / IP(src=laptop, dst=web2) / TCP(sport=sport, dport=4444, flags="S"))
for i in range(4):
    add(Ether(src=MAC_A, dst=MAC_B) / IP(src=laptop, dst=web2) / TCP(sport=sport, dport=4444, flags="PA") / Raw(b"a" * 60))

wrpcap("sample.pcap", packets)
print("wrote sample.pcap with " + str(len(packets)) + " packets")
