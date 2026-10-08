from scapy.all import sniff, ARP
import time

from security_event import SecurityEvent


# ============================================================
# Configuration
# ============================================================

TARGET_IP = "192.168.56.105"
INTERFACE = "enp0s8"

CONFIDENCE = 0.95


# ============================================================
# ARP Mapping
# ============================================================

# IP address -> MAC address
arp_table = {}


# ============================================================
# ARP Spoof Detection
# ============================================================

def detect_arp_spoof(packet, commander):

    # --------------------------------------------------------
    # Check ARP layer
    # --------------------------------------------------------

    if not packet.haslayer(ARP):
        return

    arp = packet[ARP]

    # --------------------------------------------------------
    # We are interested in ARP replies
    # --------------------------------------------------------

    if arp.op != 2:
        return

    # --------------------------------------------------------
    # Source IP and MAC
    # --------------------------------------------------------

    source_ip = arp.psrc
    source_mac = arp.hwsrc

    # --------------------------------------------------------
    # Ignore unrelated IPs
    # --------------------------------------------------------

    if source_ip != TARGET_IP:
        return

    # ========================================================
    # First observation
    # ========================================================

    if source_ip not in arp_table:

        arp_table[source_ip] = source_mac

        print(
            f"[ARP BASELINE] "
            f"{source_ip} -> {source_mac}"
        )

        return

    # ========================================================
    # Existing mapping
    # ========================================================

    known_mac = arp_table[source_ip]

    # --------------------------------------------------------
    # Mapping hasn't changed
    # --------------------------------------------------------

    if known_mac == source_mac:

        return

    # ========================================================
    # MAC address changed
    # ========================================================

    print("\n" + "=" * 60)
    print("[ALERT] ARP SPOOFING DETECTED")
    print("=" * 60)

    print(f"IP Address      : {source_ip}")
    print(f"Known MAC       : {known_mac}")
    print(f"New MAC         : {source_mac}")
    print(f"Confidence      : {CONFIDENCE}")

    print("=" * 60)

    # --------------------------------------------------------
    # Create Security Event
    # --------------------------------------------------------

    event = SecurityEvent(
        event_type="ARP_SPOOFING",
        source_ip=source_ip,
        target_ip=TARGET_IP,
        service_port=0,
        failed_attempts=1,
        window_seconds=0,
        confidence=CONFIDENCE,
        timestamp=time.time()
    )

    print("\n[SECURITY EVENT]")
    print(event.to_json())

    # --------------------------------------------------------
    # Send to Cyber Commander
    # --------------------------------------------------------

    print(
        "\n[+] Sending ARP_SPOOFING event "
        "to Decision Engine..."
    )

    commander.publish_event(event)

    # --------------------------------------------------------
    # Update mapping
    # --------------------------------------------------------

    arp_table[source_ip] = source_mac


# ============================================================
# Start Detector
# ============================================================

def start_detector(commander):

    try:

        print("\n[*] ARP Spoof Detector started.")

        print(
            f"[*] Monitoring target : {TARGET_IP}"
        )

        print(
            f"[*] Interface         : {INTERFACE}"
        )

        print(
            "\n[*] Monitoring ARP traffic...\n"
        )

        sniff(
            iface=INTERFACE,

            filter="arp",

            prn=lambda packet:
                detect_arp_spoof(
                    packet,
                    commander
                ),

            store=False
        )

    except PermissionError:

        print(
            "\n[ERROR] ARP packet capture "
            "requires root privileges."
        )

    except KeyboardInterrupt:

        print(
            "\n[*] ARP Spoof Detector stopped."
        )

    except Exception as e:

        print(
            f"\n[ERROR] ARP Spoof Detector failed: {e}"
        )


# ============================================================
# Entry Point
# ============================================================

if __name__ == "__main__":

    print(
        "[ERROR] This detector requires "
        "a Cyber Commander object."
    )

    print(
        "[INFO] Start it from cyber_commander.py:"
    )

    print(
        "start_detector(commander)"
    )
