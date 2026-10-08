class FirewallTools:

    def __init__(self, firewall_manager):

        self.firewall = firewall_manager


    def block_ip(
        self,
        ip: str,
        duration: int,
        reason: str
    ) -> dict:
        """
        Block a source IP using the eBPF/XDP firewall.

        Args:
            ip: Source IPv4 address to block.
            duration: Number of seconds to keep the IP blocked.
            reason: Security reason for the block.

        Returns:
            Result of the firewall operation.
        """

        print("\n" + "=" * 60)
        print("[FIREWALL TOOL] BLOCK IP REQUEST")
        print("=" * 60)

        print(f"IP       : {ip}")
        print(f"Duration : {duration}s")
        print(f"Reason   : {reason}")

        # Safety validation
        if not ip:
            return {
                "success": False,
                "error": "Missing IP address"
            }

        if duration <= 0:
            return {
                "success": False,
                "error": "Duration must be greater than zero"
            }

        # Limit AI-generated duration
        if duration > 3600:
            duration = 3600

            print(
                "[FIREWALL TOOL] "
                "Duration capped at 3600 seconds."
            )

        try:

            self.firewall.block_ip(
                ip,
                duration=duration
            )

            print(
                "[FIREWALL TOOL] "
                "Firewall rule successfully deployed."
            )

            return {
                "success": True,
                "action": "BLOCK",
                "ip": ip,
                "duration": duration,
                "reason": reason
            }

        except Exception as e:

            print(
                f"[FIREWALL TOOL] "
                f"Firewall operation failed: {e}"
            )

            return {
                "success": False,
                "error": str(e)
            }
