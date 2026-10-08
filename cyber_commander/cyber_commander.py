import threading
import time

from firewall_manager import FirewallManager
from firewall_tools import FirewallTools
from ai_agent import CyberDefenseAgent

from event_bus import EventBus
from decision_engine import DecisionEngine
from attack_correlator import AttackCorrelator
from attack_memory import AttackMemory

from syn_flood_detector import start_detector as start_syn_detector
from http_detector import start_detector as start_http_detector
from icmp_flood_detector import start_detector as start_icmp_detector
from brute_force_detector import start_detector as start_brute_detector
from port_scan_detector import start_detector as start_port_scan_detector
from arp_spoof_detector import start_detector as start_arp_detector


# ============================================================
# Configuration
# ============================================================

BPF_SOURCE = (
    "/home/kali/AI_cyber_commander/eBPF.c"
)

INTERFACE = "enp0s8"


# ============================================================
# Autonomous AI Cyber Commander
# ============================================================

class CyberCommander:

    def __init__(self):

        print("=" * 60)
        print("          AUTONOMOUS AI CYBER COMMANDER")
        print("=" * 60)

        # ====================================================
        # 1. FIREWALL MANAGER
        # ====================================================

        print(
            "\n[*] Initializing Firewall Manager..."
        )

        self.firewall = FirewallManager(

            bpf_source=BPF_SOURCE,

            interface=INTERFACE
        )

        # ====================================================
        # 2. FIREWALL TOOLS
        # ====================================================

        print(
            "[*] Initializing Firewall Tools..."
        )

        self.firewall_tools = FirewallTools(

            self.firewall
        )

        # ====================================================
        # 3. GEMINI AI AGENT
        # ====================================================

        print(
            "[*] Initializing Gemini AI Agent..."
        )

        self.ai_agent = CyberDefenseAgent(

            self.firewall_tools
        )

        # ====================================================
        # 4. ATTACK MEMORY
        # ====================================================

        print(
            "[*] Initializing Attack Memory..."
        )

        self.attack_memory = AttackMemory()

        # ====================================================
        # 5. DECISION ENGINE
        # ====================================================

        print(
            "[*] Initializing Decision Engine..."
        )

        self.decision_engine = DecisionEngine(

            ai_agent=self.ai_agent,

            firewall_tools=self.firewall_tools,

            attack_memory=self.attack_memory
        )

        # ====================================================
        # 6. EVENT BUS
        # ====================================================

        print(
            "[*] Initializing Event Bus..."
        )

        self.event_bus = EventBus()

        # ====================================================
        # 7. ATTACK CORRELATOR
        # ====================================================

        print(
            "[*] Initializing Attack Correlator..."
        )

        self.correlator = AttackCorrelator()

        # ====================================================
        # INITIALIZATION COMPLETE
        # ====================================================

        print()
        print("=" * 60)
        print("[+] CYBER COMMANDER INITIALIZED")
        print("=" * 60)

        print(
            "[+] Firewall Manager : READY"
        )

        print(
            "[+] Firewall Tools   : READY"
        )

        print(
            "[+] Gemini AI Agent  : READY"
        )

        print(
            "[+] Attack Memory    : READY"
        )

        print(
            "[+] Decision Engine  : READY"
        )

        print(
            "[+] Event Bus        : READY"
        )

        print(
            "[+] Attack Correlator: READY"
        )

        print("=" * 60)

    # ========================================================
    # PUBLISH SECURITY EVENT
    # ========================================================

    def publish_event(self, event):

        print(
            "[CYBER COMMANDER] "
            f"Publishing event: {event.event_type}"
        )

        self.event_bus.publish(
            event
        )

    # ========================================================
    # PROCESS SECURITY EVENTS
    # ========================================================

    def process_events(self):

        print()
        print(
            "[*] Event processing engine started."
        )

        while True:

            # ------------------------------------------------
            # Wait for event
            # ------------------------------------------------

            event = self.event_bus.get_event()

            print()
            print("=" * 60)
            print(
                "[CYBER COMMANDER] "
                "SECURITY EVENT RECEIVED"
            )
            print("=" * 60)

            print(
                f"Event      : "
                f"{event.event_type}"
            )

            print(
                f"Source     : "
                f"{event.source_ip}"
            )

            print(
                f"Target     : "
                f"{event.target_ip}"
            )

            print(
                f"Confidence : "
                f"{event.confidence}"
            )

            # =================================================
            # ATTACK CORRELATION
            # =================================================

            correlation = (
                self.correlator.add_event(
                    event
                )
            )

            # ------------------------------------------------
            # Display correlation
            # ------------------------------------------------

            if correlation:

                self.correlator.print_correlation(

                    correlation
                )

            # =================================================
            # DECISION ENGINE
            # =================================================

            try:

                result = (
                    self.decision_engine.process_event(

                        event,

                        correlation
                    )
                )

                print()
                print(
                    "[CYBER COMMANDER] "
                    "Decision processing completed."
                )

                if isinstance(
                    result,
                    dict
                ):

                    print(
                        "[CYBER COMMANDER] "
                        f"Action: "
                        f"{result.get('action')}"
                    )

            except Exception as e:

                print()
                print(
                    "[CYBER COMMANDER] "
                    f"Decision processing failed: {e}"
                )

    # ========================================================
    # START COMMANDER
    # ========================================================

    def start(self):

        print()
        print("=" * 60)
        print(
            "STARTING AUTONOMOUS CYBER COMMANDER"
        )
        print("=" * 60)

        # ====================================================
        # EVENT PROCESSING THREAD
        # ====================================================

        event_thread = threading.Thread(

            target=self.process_events,

            daemon=True
        )

        event_thread.start()

        print(
            "[+] Event processing thread started."
        )

        # ====================================================
        # DETECTORS
        # ====================================================

        detectors = [

            (
                "SYN Flood",
                start_syn_detector
            ),

            (
                "HTTP Flood",
                start_http_detector
            ),

            (
                "ICMP Flood",
                start_icmp_detector
            ),

            (
                "Brute Force",
                start_brute_detector
            ),

            (
                "Port Scan",
                start_port_scan_detector
            ),

            (
                "ARP Spoofing",
                start_arp_detector
            )
        ]

        # ====================================================
        # START DETECTORS
        # ====================================================

        for name, detector in detectors:

            try:

                thread = threading.Thread(

                    target=detector,

                    args=(self,),

                    daemon=True
                )

                thread.start()

                print(
                    f"[+] {name} detector started."
                )

            except Exception as e:

                print(
                    f"[ERROR] Failed to start "
                    f"{name} detector: {e}"
                )

        # ====================================================
        # SYSTEM STATUS
        # ====================================================

        print()
        print("=" * 60)
        print(
            "      AUTONOMOUS CYBER COMMANDER RUNNING"
        )
        print("=" * 60)

        print(
            "[+] Event Bus             : ACTIVE"
        )

        print(
            "[+] Attack Correlator     : ACTIVE"
        )

        print(
            "[+] Attack Memory         : ACTIVE"
        )

        print(
            "[+] Gemini AI Agent       : ACTIVE"
        )

        print(
            "[+] Decision Engine       : ACTIVE"
        )

        print(
            "[+] Firewall Tools        : ACTIVE"
        )

        print(
            "[+] Firewall Manager      : ACTIVE"
        )

        print(
            "[+] eBPF/XDP Firewall     : ACTIVE"
        )

        print()

        print(
            "[+] SYN Flood Detector    : ACTIVE"
        )

        print(
            "[+] HTTP Flood Detector   : ACTIVE"
        )

        print(
            "[+] ICMP Flood Detector   : ACTIVE"
        )

        print(
            "[+] Brute Force Detector  : ACTIVE"
        )

        print(
            "[+] Port Scan Detector    : ACTIVE"
        )

        print(
            "[+] ARP Spoofing Detector : ACTIVE"
        )

        print("=" * 60)

        # ====================================================
        # KEEP RUNNING
        # ====================================================

        try:

            while True:

                time.sleep(1)

        except KeyboardInterrupt:

            print()
            print(
                "[*] Cyber Commander "
                "shutdown requested."
            )

        finally:

            self.shutdown()

    # ========================================================
    # SHUTDOWN
    # ========================================================

    def shutdown(self):

        print()
        print("=" * 60)
        print("CYBER COMMANDER SHUTDOWN")
        print("=" * 60)

        # ----------------------------------------------------
        # Display attack history
        # ----------------------------------------------------

        try:

            self.attack_memory.display_history()

        except Exception as e:

            print(
                "[ERROR] Failed to display "
                f"attack history: {e}"
            )

        # ----------------------------------------------------
        # Cleanup firewall
        # ----------------------------------------------------

        try:

            self.firewall.cleanup()

        except Exception as e:

            print(
                "[ERROR] Firewall cleanup failed: "
                f"{e}"
            )

        print()
        print(
            "[+] Cyber Commander shutdown complete."
        )

        print("=" * 60)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    commander = CyberCommander()

    commander.start()
