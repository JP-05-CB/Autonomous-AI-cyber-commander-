from bcc import BPF
import socket
import struct
import ctypes as ct
import threading


class FirewallManager:

    def __init__(self, bpf_source, interface):

        self.bpf_source = bpf_source
        self.interface = interface

        # Stores active automatic-unblock timers.
        #
        # Example:
        #
        # {
        #     "192.168.56.103": <Timer object>
        # }
        #
        self.active_timers = {}

        print("=" * 60)
        print("CYBER COMMANDER - FIREWALL MANAGER")
        print("=" * 60)

        print(f"BPF source : {self.bpf_source}")
        print(f"Interface  : {self.interface}")

        # ====================================================
        # Load eBPF program
        # ====================================================

        print()
        print("[*] Loading eBPF program...")

        self.b = BPF(
            src_file=self.bpf_source
        )

        # ====================================================
        # Load XDP function
        # ====================================================

        print("[*] Loading XDP firewall function...")

        self.function = self.b.load_func(
            "xdp_firewall",
            BPF.XDP
        )

        # ====================================================
        # Attach XDP
        # ====================================================

        print()
        print("[*] Attaching XDP...")

        self.b.attach_xdp(
            self.interface,
            self.function,
            0
        )

        print("[+] XDP firewall attached.")

        # ====================================================
        # Get BPF maps
        # ====================================================

        print()
        print("[*] Loading BPF maps...")

        self.blocklist = self.b["blocklist"]

        self.total_packets = self.b["total_packets"]

        print("[+] BPF maps loaded.")

        print()
        print("[+] Firewall Manager ready.")
        print("=" * 60)

    # ========================================================
    # IP conversion
    # ========================================================

    @staticmethod
    def ip_to_u32(ip):

        return struct.unpack(
            "I",
            socket.inet_aton(ip)
        )[0]

    @staticmethod
    def u32_to_ip(value):

        return socket.inet_ntoa(
            struct.pack(
                "I",
                int(value)
            )
        )

    # ========================================================
    # BLOCK IP
    # ========================================================

    def block_ip(self, ip, duration=60):

        # ----------------------------------------------------
        # Validate IP address
        # ----------------------------------------------------

        try:

            self.ip_to_u32(ip)

        except OSError:

            raise ValueError(
                f"Invalid IPv4 address: {ip}"
            )

        # ----------------------------------------------------
        # Validate duration
        # ----------------------------------------------------

        if duration <= 0:

            raise ValueError(
                "Block duration must be greater than zero."
            )

        # Maximum block duration:
        # 1 hour
        #
        if duration > 3600:

            print(
                "[FIREWALL] Requested duration exceeds "
                "maximum limit."
            )

            print(
                "[FIREWALL] Duration capped at 3600 seconds."
            )

            duration = 3600

        # ----------------------------------------------------
        # Convert IP to BPF map key
        # ----------------------------------------------------

        key = ct.c_uint32(
            self.ip_to_u32(ip)
        )

        value = ct.c_uint64(0)

        # ----------------------------------------------------
        # Add IP to eBPF blocklist
        # ----------------------------------------------------

        self.blocklist[key] = value

        print()
        print("🚨 AUTONOMOUS FIREWALL ACTION")
        print("=" * 60)
        print(f"Source IP : {ip}")
        print("Action    : BLOCK")
        print(f"Duration  : {duration} seconds")
        print("Mechanism : eBPF/XDP")
        print("Result    : XDP_DROP")
        print("=" * 60)

        # ----------------------------------------------------
        # Cancel previous timer
        # ----------------------------------------------------

        if ip in self.active_timers:

            old_timer = self.active_timers[ip]

            old_timer.cancel()

            print(
                f"[FIREWALL] Existing timer for "
                f"{ip} cancelled."
            )

        # ----------------------------------------------------
        # Create automatic unblock timer
        # ----------------------------------------------------

        timer = threading.Timer(
            duration,
            self.unblock_ip,
            args=(ip,)
        )

        # Timer should not keep the entire program alive.
        timer.daemon = True

        timer.start()

        self.active_timers[ip] = timer

        print(
            f"[FIREWALL] Automatic unblock scheduled "
            f"in {duration} seconds."
        )

    # ========================================================
    # UNBLOCK IP
    # ========================================================

    def unblock_ip(self, ip):

        # ----------------------------------------------------
        # Convert IP to BPF map key
        # ----------------------------------------------------

        key = ct.c_uint32(
            self.ip_to_u32(ip)
        )

        try:

            # ------------------------------------------------
            # Remove IP from eBPF blocklist
            # ------------------------------------------------

            del self.blocklist[key]

            print()
            print("✅ FIREWALL RULE REMOVED")
            print("=" * 60)
            print(f"Source IP : {ip}")
            print("Action    : UNBLOCK")
            print("Reason    : Block duration expired")
            print("=" * 60)

        except KeyError:

            print(
                f"[FIREWALL] {ip} is not currently "
                f"in the blocklist."
            )

        finally:

            # ------------------------------------------------
            # Remove timer reference
            # ------------------------------------------------

            self.active_timers.pop(
                ip,
                None
            )

    # ========================================================
    # LIST BLOCKED IPs
    # ========================================================

    def list_blocked(self):

        print()
        print("=" * 60)
        print("ACTIVE BLOCKLIST")
        print("=" * 60)

        # ----------------------------------------------------
        # Check whether blocklist is empty
        # ----------------------------------------------------

        if len(self.blocklist) == 0:

            print("No blocked IPs.")

            return

        # ----------------------------------------------------
        # Display every blocked IP
        # ----------------------------------------------------

        for key, value in self.blocklist.items():

            ip = self.u32_to_ip(
                key.value
            )

            dropped = value.value

            print(
                f"{ip:20} "
                f"dropped_packets={dropped}"
            )

    # ========================================================
    # FIREWALL STATISTICS
    # ========================================================

    def stats(self):

        value = self.total_packets[0]

        print(
            f"Total IPv4 packets observed: "
            f"{value.value}"
        )

    # ========================================================
    # CLEANUP
    # ========================================================

    def cleanup(self):

        print()
        print("=" * 60)
        print("FIREWALL MANAGER CLEANUP")
        print("=" * 60)

        # ----------------------------------------------------
        # Cancel all active timers
        # ----------------------------------------------------

        if self.active_timers:

            print(
                "[*] Cancelling active unblock timers..."
            )

            for ip, timer in list(
                self.active_timers.items()
            ):

                timer.cancel()

                print(
                    f"[+] Timer cancelled for {ip}"
                )

            self.active_timers.clear()

        # ----------------------------------------------------
        # Remove XDP program
        # ----------------------------------------------------

        print()
        print("[*] Removing XDP firewall...")

        self.b.remove_xdp(
            self.interface,
            0
        )

        print("[+] XDP firewall detached.")

        print("=" * 60)
