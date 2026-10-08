from scapy.all import sniff, IP, ICMP
import time
from collections import defaultdict, deque

from security_event import SecurityEvent


TARGET_IP = "192.168.56.105"
INTERFACE = "enp0s8"

PACKET_THRESHOLD = 50
WINDOW_SECONDS = 5

icmp_history = defaultdict(deque)


def detect_icmp_flood(packet, commander):

    if not packet.haslayer(IP):
        return

    if packet[IP].dst != TARGET_IP:
        return

    if not packet.haslayer(ICMP):
        return

    source_ip = packet[IP].src
    current_time = time.time()

    packets = icmp_history[source_ip]

    while packets and (
        current_time - packets[0] > WINDOW_SECONDS
    ):
        packets.popleft()

    packets.append(current_time)

    count = len(packets)

    print(
        f"[ICMP] "
        f"{source_ip} -> "
        f"{TARGET_IP} "
        f"packets={count}"
    )

    if count >= PACKET_THRESHOLD:

        event = SecurityEvent(
            event_type="ICMP_FLOOD",
            source_ip=source_ip,
            target_ip=TARGET_IP,
            service_port=0,
            failed_attempts=count,
            window_seconds=WINDOW_SECONDS,
            confidence=0.95,
            timestamp=time.time()
        )

        print("\n[ALERT] ICMP FLOOD DETECTED")

        print("\n[SECURITY EVENT]")
        print(event.to_json())

        commander.publish_event(event)

        packets.clear()


def start_detector(commander):

    print("[+] ICMP Flood Detector started.")

    sniff(
        iface=INTERFACE,
        filter="icmp",
        prn=lambda packet: detect_icmp_flood(
            packet,
            commander
        ),
        store=False
    )
