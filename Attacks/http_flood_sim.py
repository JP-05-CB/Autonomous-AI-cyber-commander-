import urllib.request
import time

TARGET = "192.168.56.105"
PORT = 8080

REQUEST_COUNT = 100
DELAY = 0.02

URL = f"http://{TARGET}:{PORT}/"

print("=" * 60)
print("        HTTP REQUEST FLOOD SIMULATOR")
print("=" * 60)
print(f"Target      : {TARGET}")
print(f"Port        : {PORT}")
print(f"Requests    : {REQUEST_COUNT}")
print(f"Delay       : {DELAY} seconds")
print("=" * 60)

for i in range(REQUEST_COUNT):

    try:
        response = urllib.request.urlopen(
            URL,
            timeout=2
        )

        response.read()

        print(
            f"[REQUEST {i + 1:03d}] "
            f"HTTP {response.status}"
        )

    except Exception as e:

        print(
            f"[REQUEST {i + 1:03d}] "
            f"ERROR: {e}"
        )

    time.sleep(DELAY)

print("\n[*] HTTP flood simulation completed.")
