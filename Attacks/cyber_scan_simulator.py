import socket
import time


TARGET = "192.168.56.105"

PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    135,
    139,
    443,
    445,
    8080,
]


print("=" * 60)
print("CYBER COMMANDER - CONTROLLED TEST SIMULATOR")
print("=" * 60)

print(f"Target: {TARGET}")
print(f"Ports : {len(PORTS)}")
print()


for port in PORTS:

    print(f"Testing {TARGET}:{port}")

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(0.2)

    try:
        sock.connect((TARGET, port))
        print("  Connection accepted")

    except (ConnectionRefusedError, socket.timeout, OSError):
        print("  No connection")

    finally:
        sock.close()

    time.sleep(0.1)


print()
print("Simulation complete.")
