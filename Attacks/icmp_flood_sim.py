from scapy.all import IP, ICMP, send
import time

TARGET = "192.168.56.105"
#TARGET = "10.0.2.0"

PACKET_COUNT = 100
DELAY = 0.02

print("=" * 60)
print("           ICMP FLOOD SIMULATOR")
print("=" * 60)
print(f"Target      : {TARGET}")
print(f"Packets     : {PACKET_COUNT}")
print(f"Delay       : {DELAY} seconds")
print("=" * 60)

packet = IP(dst=TARGET) / ICMP()

for i in range(PACKET_COUNT):

    send(
        packet,
        verbose=False
    )

    print(f"[ICMP {i + 1:03d}] sent")

    time.sleep(DELAY)

print("\n[*] ICMP simulation completed.")
