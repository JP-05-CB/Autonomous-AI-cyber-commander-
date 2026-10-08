from scapy.all import IP, UDP, DNS, DNSQR, send
import random
import string
import time

# ============================================================
# CONFIGURATION
# ============================================================

TARGET = "192.168.56.105"

DNS_SERVER = TARGET
DNS_PORT = 53

DOMAIN = "lab-c2.example"

QUERY_COUNT = 100
DELAY = 0.05

# ============================================================
# GENERATE RANDOM SUBDOMAIN
# ============================================================

def random_label(length=45):

    characters = string.ascii_lowercase + string.digits

    return "".join(
        random.choice(characters)
        for _ in range(length)
    )


# ============================================================
# START SIMULATION
# ============================================================

print("=" * 60)
print("          DNS TUNNEL / BEACON SIMULATOR")
print("=" * 60)

print(f"DNS server  : {DNS_SERVER}")
print(f"Domain      : {DOMAIN}")
print(f"Queries     : {QUERY_COUNT}")
print(f"Delay       : {DELAY}s")
print("=" * 60)

print("\nStarting DNS traffic simulation...\n")

for i in range(QUERY_COUNT):

    label = random_label()

    query_name = f"{label}.{DOMAIN}"

    packet = (
        IP(
            dst=DNS_SERVER
        )
        /
        UDP(
            dport=DNS_PORT
        )
        /
        DNS(
            rd=1,
            qd=DNSQR(
                qname=query_name,
                qtype="A"
            )
        )
    )

    send(
        packet,
        verbose=False
    )

    print(
        f"[{i + 1:03d}/{QUERY_COUNT}] "
        f"DNS query → {query_name}"
    )

    time.sleep(DELAY)

print("\n" + "=" * 60)
print("DNS TRAFFIC SIMULATION COMPLETED")
print("=" * 60)
