from scapy.all import IP, ICMP, fragment, send
import time

TARGET = "192.168.56.105"

PACKETS = 60
DELAY = 0.1

print("=" * 60)
print("          IP FRAGMENTATION SIMULATOR")
print("=" * 60)

print(f"Target  : {TARGET}")
print(f"Packets : {PACKETS}")
print("=" * 60)

payload = b"A" * 3000

for i in range(PACKETS):

    packet = (
        IP(dst=TARGET)
        /
        ICMP()
        /
        payload
    )

    fragments = fragment(
        packet,
        fragsize=400
    )

    send(
        fragments,
        verbose=False
    )

    print(
        f"[{i + 1:02d}/{PACKETS}] "
        f"Fragmented packet sent"
    )

    time.sleep(DELAY)

print("\nFragmentation test completed.")
