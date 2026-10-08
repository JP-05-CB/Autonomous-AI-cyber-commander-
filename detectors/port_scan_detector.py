from scapy.all import sniff, IP, TCP, UDP
import time
from collections import defaultdict, deque

from security_event import SecurityEvent


# ============================================================
# Configuration
# ============================================================

TARGET_IP = "192.168.56.105"
INTERFACE = "enp0s8"

PORT_THRESHOLD = 10
WINDOW_SECONDS = 5


# ============================================================
# Port scan history
# ============================================================

# Structure:
#
# source_ip -> deque(
#     (timestamp, destination_port)
# )
#
port_history = defaultdict(deque)


# ============================================================
# Port Scan Detection
# ============================================================

def detect_port_scan(packet, commander):

    # --------------------------------------------------------
    # Check IP layer
    # --------------------------------------------------------

    if not packet.haslayer(IP):
        return

    # Only monitor the protected machine
    if packet[IP].dst != TARGET_IP:
        return

    # --------------------------------------------------------
    # Check TCP / UDP
    # --------------------------------------------------------

    if packet.haslayer(TCP):

        destination_port = packet[TCP].dport

    elif packet.haslayer(UDP):

        destination_port = packet[UDP].dport

    else:
        return

    # --------------------------------------------------------
    # Source IP
    # --------------------------------------------------------

    source_ip = packet[IP].src
    current_time = time.time()

    history = port_history[source_ip]

    # --------------------------------------------------------
    # Remove old entries
    # --------------------------------------------------------

    while history and (
        current_time - history[0][0] > WINDOW_SECONDS
    ):
        history.popleft()

    # --------------------------------------------------------
    # Record packet
    # --------------------------------------------------------

    history.append(
        (
            current_time,
            destination_port
        )
    )

    # --------------------------------------------------------
    # Extract unique destination ports
    # --------------------------------------------------------

    unique_ports = {
        port
        for timestamp, port in history
    }

    port_count = len(unique_ports)

    # --------------------------------------------------------
    # Display activity
    # --------------------------------------------------------

    print(
        f"[PORT ACTIVITY] "
        f"{source_ip} -> "
        f"{TARGET_IP} "
        f"unique_ports={port_count}"
    )

    # ========================================================
    # Detect Port Scan
    # ========================================================

    if port_count >= PORT_THRESHOLD:

        event = SecurityEvent(
            event_type="PORT_SCAN",
            source_ip=source_ip,
            target_ip=TARGET_IP,
            service_port=0,
            failed_attempts=port_count,
            window_seconds=WINDOW_SECONDS,
            confidence=0.90,
            timestamp=time.time()
        )

        # ----------------------------------------------------
        # Alert
        # ----------------------------------------------------

        print("\n" + "=" * 60)
        print("[ALERT] PORT SCAN DETECTED")
        print("=" * 60)

        print(f"Source IP       : {source_ip}")
        print(f"Target IP       : {TARGET_IP}")
        print(f"Unique ports    : {port_count}")
        print(f"Ports           : {sorted(unique_ports)}")
        print(f"Time window     : {WINDOW_SECONDS} seconds")
        print(f"Confidence      : 0.90")

        print("=" * 60)

        # ----------------------------------------------------
        # Security Event
        # ----------------------------------------------------

        print("\n[SECURITY EVENT]")
        print(event.to_json())

        # ----------------------------------------------------
        # Send to Cyber Commander
        # ----------------------------------------------------

        print(
            "\n[+] Sending PORT_SCAN event "
            "to Decision Engine..."
        )

        commander.publish_event(event)

        # ----------------------------------------------------
        # Reset history
        # ----------------------------------------------------

        history.clear()


# ============================================================
# Start Detector
# ============================================================

def start_detector(commander):

    try:

        print("\n[*] Port Scan Detector started.")

        print(
            f"[*] Monitoring target : {TARGET_IP}"
        )

        print(
            f"[*] Interface         : {INTERFACE}"
        )

        print(
            f"[*] Port threshold    : "
            f"{PORT_THRESHOLD} unique ports"
        )

        print(
            f"[*] Time window       : "
            f"{WINDOW_SECONDS} seconds"
        )

        print(
            "\n[*] Waiting for port scanning activity...\n"
        )

        # ----------------------------------------------------
        # Capture TCP and UDP traffic
        # ----------------------------------------------------

        sniff(
            iface=INTERFACE,

            filter="tcp or udp",

            prn=lambda packet:
                detect_port_scan(
                    packet,
                    commander
                ),

            store=False
        )

    except PermissionError:

        print(
            "\n[ERROR] Packet capture requires "
            "root privileges."
        )

        print(
            "[ERROR] Run the Commander using sudo."
        )

    except KeyboardInterrupt:

        print(
            "\n[*] Port Scan Detector stopped."
        )

    except Exception as e:

        print(
            f"\n[ERROR] Port Scan Detector failed: {e}"
        )


# ============================================================
# Entry Point
# ============================================================

if __name__ == "__main__":

    print(
        "[ERROR] This detector requires a "
        "Cyber Commander object."
    )

    print(
        "[INFO] Start it from your main Commander:"
    )

    print(
        "start_detector(commander)"
    )
