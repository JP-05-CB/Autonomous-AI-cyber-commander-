from scapy.all import IP, TCP, send
import random
import time

# ============================================================
# CONFIGURATION
# ============================================================

TARGET = "192.168.56.105"

START_PORT = 1
END_PORT = 100

DELAY = 0.03

print("=" * 60)
print("             TCP FIN SCAN SIMULATOR")
print("=" * 60)

print(f"Target      : {TARGET}")
print(f"Port range  : {START_PORT}-{END_PORT}")
print(f"Delay       : {DELAY}s")
print("=" * 60)

print("\nStarting TCP FIN scan...\n")

for port in range(START_PORT, END_PORT + 1):

    packet = (
        IP(dst=TARGET) /
        TCP(
            sport=random.randint(1024, 65535),
            dport=port,
            flags="F"
        )
    )

    send(
        packet,
        verbose=False
    )

    print(
        f"[{port:03d}] FIN sent → "
        f"{TARGET}:{port}"
    )

    time.sleep(DELAY)

print("\n" + "=" * 60)
print("TCP FIN SCAN COMPLETED")
print("=" * 60)
