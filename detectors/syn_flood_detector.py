from scapy.all import sniff, IP, TCP
import time
from collections import defaultdict, deque

from security_event import SecurityEvent
# from decision_engine import DecisionEngine
# from firewall_manager import FirewallManager


# ============================================================
# Configuration
# ============================================================

TARGET_IP = "192.168.56.105"
TARGET_PORT = 8080
INTERFACE = "enp0s8"

SYN_THRESHOLD = 50
WINDOW_SECONDS = 5


# ============================================================
# Track SYN packets
# ============================================================

syn_history = defaultdict(deque)


# ============================================================
# SYN Flood Detection
# ============================================================

def detect_syn_flood(packet, commander):

    # --------------------------------------------------------
    # Check IP layer
    # --------------------------------------------------------

    if not packet.haslayer(IP):
        return

    if packet[IP].dst != TARGET_IP:
        return

    # --------------------------------------------------------
    # Check TCP layer
    # --------------------------------------------------------

    if not packet.haslayer(TCP):
        return

    if packet[TCP].dport != TARGET_PORT:
        return

    # --------------------------------------------------------
    # Check SYN flag
    # --------------------------------------------------------

    # SYN flag = 0x02
    if not (packet[TCP].flags & 0x02):
        return

    # Ignore SYN + ACK packets
    # ACK flag = 0x10
    if packet[TCP].flags & 0x10:
        return

    # --------------------------------------------------------
    # Get source IP and current time
    # --------------------------------------------------------

    source_ip = packet[IP].src
    current_time = time.time()

    syn_packets = syn_history[source_ip]

    # --------------------------------------------------------
    # Remove SYN packets outside the time window
    # --------------------------------------------------------

    while syn_packets and (
        current_time - syn_packets[0] > WINDOW_SECONDS
    ):
        syn_packets.popleft()

    # --------------------------------------------------------
    # Record current SYN packet
    # --------------------------------------------------------

    syn_packets.append(current_time)

    count = len(syn_packets)

    print(
        f"[TCP SYN] "
        f"{source_ip} -> "
        f"{TARGET_IP}:{TARGET_PORT} "
        f"SYNs={count}"
    )

    # ========================================================
    # Detect SYN flood
    # ========================================================

    if count >= SYN_THRESHOLD:

        event = SecurityEvent(
            event_type="SYN_FLOOD",
            source_ip=source_ip,
            target_ip=TARGET_IP,
            service_port=TARGET_PORT,
            failed_attempts=count,
            window_seconds=WINDOW_SECONDS,
            confidence=0.95,
            timestamp=time.time()
        )

        # ----------------------------------------------------
        # Print alert
        # ----------------------------------------------------

        print("\n" + "=" * 60)
        print("[ALERT] TCP SYN FLOOD DETECTED")
        print("=" * 60)

        print(f"Source IP       : {source_ip}")
        print(f"Target IP       : {TARGET_IP}")
        print(f"Target port     : {TARGET_PORT}")
        print(f"SYN packets     : {count}")
        print(f"Time window     : {WINDOW_SECONDS} seconds")
        print(f"Confidence      : 0.95")

        print("=" * 60)

        # ----------------------------------------------------
        # Display Security Event
        # ----------------------------------------------------

        print("\n[SECURITY EVENT]")
        print(event.to_json())

        # ----------------------------------------------------
        # Send event to Autonomous AI Cyber Commander
        # ----------------------------------------------------

        print("\n[+] Sending event to Decision Engine...")

        commander.publish_event(event)

        # ----------------------------------------------------
        # Reset SYN history for this source
        # ----------------------------------------------------

        syn_packets.clear()


# ============================================================
# Main Detector
# ============================================================

def start_detector(commander):

    try:

        print("\n[*] SYN Flood Detector started.")

        print(
            f"[*] Monitoring "
            f"{TARGET_IP}:{TARGET_PORT}"
        )

        print(
            f"[*] Interface : {INTERFACE}"
        )

        print(
            f"[*] Threshold : {SYN_THRESHOLD} SYNs"
        )

        print(
            f"[*] Window    : {WINDOW_SECONDS} seconds"
        )

        print("\n[*] Waiting for TCP SYN packets...\n")

        # ----------------------------------------------------
        # Start packet capture
        # ----------------------------------------------------

        sniff(
            iface=INTERFACE,

            filter=f"tcp dst port {TARGET_PORT}",

            prn=lambda packet: detect_syn_flood(
                packet,
                commander
            ),

            store=False
        )

    # ========================================================
    # Error Handling
    # ========================================================

    except PermissionError:

        print(
            "\n[ERROR] Packet capture requires root privileges."
        )

        print(
            "[ERROR] Run the detector using:"
        )

        print(
            "sudo python3 syn_flood_detector.py"
        )

    except KeyboardInterrupt:

        print(
            "\n[*] SYN Flood Detector stopped."
        )

    except Exception as e:

        print(
            f"\n[ERROR] Detector failed: {e}"
        )


# ============================================================
# Entry Point
# ============================================================

if __name__ == "__main__":

    print("[ERROR] This detector requires a Commander object.")

    print(
        "[INFO] Start it from your main Autonomous AI Cyber "
        "Commander program using:"
    )

    print(
        "start_detector(commander)"
    )
