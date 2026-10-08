import socket
import time

TARGET = "192.168.56.105"
PORT = 80

print("=" * 60)
print("       HTTP REQUEST SMUGGLING TEST")
print("=" * 60)

print(f"Target : {TARGET}")
print(f"Port   : {PORT}")
print("=" * 60)

# ------------------------------------------------------------
# Controlled ambiguous HTTP request
#
# This contains both Content-Length and Transfer-Encoding.
# Different HTTP components can interpret these headers
# differently, which is the behavior we want to test.
# ------------------------------------------------------------

request = (
    b"POST /lab-test HTTP/1.1\r\n"
    b"Host: lab-test\r\n"
    b"Content-Length: 4\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"Connection: close\r\n"
    b"\r\n"
    b"0\r\n"
    b"\r\n"
)

print("\n[*] Sending controlled ambiguous HTTP request...")

try:

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(5)

    sock.connect(
        (TARGET, PORT)
    )

    sock.sendall(request)

    print("[+] Test request sent.")

    try:

        response = sock.recv(4096)

        print("\n[SERVER RESPONSE]")
        print(response.decode(
            errors="replace"
        ))

    except socket.timeout:

        print(
            "[*] Server did not respond before timeout."
        )

    sock.close()

except Exception as e:

    print(
        f"[ERROR] Connection failed: {e}"
    )

print("\n" + "=" * 60)
print("HTTP SMUGGLING TEST COMPLETED")
print("=" * 60)
