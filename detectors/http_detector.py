from scapy.all import sniff, IP, TCP, Raw
import time
from collections import defaultdict, deque

from security_event import SecurityEvent


# ============================================================
# Configuration
# ============================================================

TARGET_IP = "192.168.56.105"
HTTP_PORT = 8080
INTERFACE = "enp0s8"

REQUEST_THRESHOLD = 50
WINDOW_SECONDS = 5


# ============================================================
# Request history
# ============================================================

request_history = defaultdict(deque)


# ============================================================
# HTTP Flood Detection
# ============================================================

def detect_http_flood(packet, commander):

    if not packet.haslayer(IP):
        return

    if packet[IP].dst != TARGET_IP:
        return

    if not packet.haslayer(TCP):
        return

    if packet[TCP].dport != HTTP_PORT:
        return

    if not packet.haslayer(Raw):
        return

    try:
        payload = packet[Raw].load.decode(
            "utf-8",
            errors="ignore"
        )
    except Exception:
        return

    # Detect HTTP requests
    if not (
        payload.startswith("GET ")
        or payload.startswith("POST ")
        or payload.startswith("HEAD ")
        or payload.startswith("PUT ")
        or payload.startswith("DELETE ")
    ):
        return

    source_ip = packet[IP].src
    current_time = time.time()

    requests = request_history[source_ip]

    # Remove old requests
    while requests and (
        current_time - requests[0] > WINDOW_SECONDS
    ):
        requests.popleft()

    requests.append(current_time)

    count = len(requests)

    print(
        f"[HTTP REQUEST] "
        f"{source_ip} -> "
        f"{TARGET_IP}:{HTTP_PORT} "
        f"requests={count}"
    )

    # ========================================================
    # Detect flood
    # ========================================================

    if count >= REQUEST_THRESHOLD:

        event = SecurityEvent(
            event_type="HTTP_FLOOD",
            source_ip=source_ip,
            target_ip=TARGET_IP,
            service_port=HTTP_PORT,
            failed_attempts=count,
            window_seconds=WINDOW_SECONDS,
            confidence=0.95,
            timestamp=time.time()
        )

        print("\n[ALERT] HTTP REQUEST FLOOD DETECTED")

        print("\n[SECURITY EVENT]")
        print(event.to_json())

        # Send event to centralized EventBus
        commander.publish_event(event)

        requests.clear()


# ============================================================
# Start Detector
# ============================================================

def start_detector(commander):

    print(
        "[+] HTTP Flood Detector started."
    )

    print(
        f"[*] Monitoring "
        f"{TARGET_IP}:{HTTP_PORT}"
    )

    sniff(
        iface=INTERFACE,
        filter=f"tcp dst port {HTTP_PORT}",
        prn=lambda packet: detect_http_flood(
            packet,
            commander
        ),
        store=False
    )
