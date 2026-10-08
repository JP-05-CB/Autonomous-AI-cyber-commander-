class DecisionEngine:

    def __init__(
        self,
        ai_agent,
        firewall_tools,
        attack_memory
    ):

        self.ai_agent = ai_agent
        self.firewall_tools = firewall_tools
        self.attack_memory = attack_memory

    # ---------------------------------------------------------
    # PROCESS SECURITY EVENT
    # ---------------------------------------------------------

    def process_event(
        self,
        event,
        correlation=None
    ):

        print()
        print("=" * 70)
        print("              DECISION ENGINE")
        print("=" * 70)

        print(
            f"Attack type : {event.event_type}"
        )

        print(
            f"Source IP   : {event.source_ip}"
        )

        print(
            f"Confidence  : {event.confidence}"
        )

        # -----------------------------------------------------
        # STEP 1 — CHECK ATTACK MEMORY
        # -----------------------------------------------------

        known_attack = self.attack_memory.lookup(
            source_ip=event.source_ip,
            event_type=event.event_type
        )

        if known_attack:

            print()
            print(
                "[ATTACK MEMORY] "
                "KNOWN MALICIOUS ATTACK DETECTED"
            )

            print(
                "[DECISION ENGINE] "
                "Skipping Gemini."
            )

            duration = known_attack.get(
                "duration",
                60
            )

            if not duration:
                duration = 60

            duration = min(
                int(duration),
                3600
            )

            reason = (
                "Repeated known attack. "
                "Immediate block using stored policy."
            )

            result = self.firewall_tools.block_ip(
                ip=event.source_ip,
                duration=duration,
                reason=reason
            )

            if result.get("success"):

                self.attack_memory.record(
                    event=event,
                    action="IMMEDIATE_BLOCK",
                    duration=duration,
                    reason=reason,
                    enforce_on_repeat=True
                )

            return result

        # -----------------------------------------------------
        # STEP 2 — NEW ATTACK
        # -----------------------------------------------------

        print()
        print(
            "[ATTACK MEMORY] "
            "New attack pattern."
        )

        print(
            "[DECISION ENGINE] "
            "Sending event to Gemini..."
        )

        try:

            result = self.ai_agent.analyze_event(
                event,
                correlation
            )

        except Exception as e:

            print(
                f"[DECISION ENGINE] "
                f"AI error: {e}"
            )

            self.attack_memory.record(
                event=event,
                action="LOG_ONLY",
                duration=None,
                reason=f"AI error: {e}",
                enforce_on_repeat=False
            )

            return {
                "success": False,
                "action": "LOG_ONLY",
                "reason": str(e)
            }

        # -----------------------------------------------------
        # STEP 3 — VALIDATE AI RESULT
        # -----------------------------------------------------

        if not isinstance(result, dict):

            print(
                "[DECISION ENGINE] "
                "Invalid AI response."
            )

            self.attack_memory.record(
                event=event,
                action="LOG_ONLY",
                reason="Invalid AI response.",
                enforce_on_repeat=False
            )

            return {
                "success": False,
                "action": "LOG_ONLY"
            }

        action = result.get(
            "action",
            "LOG_ONLY"
        )

        success = result.get(
            "success",
            False
        )

        duration = result.get(
            "duration"
        )

        reason = result.get(
            "reason",
            "No reason provided."
        )

        # -----------------------------------------------------
        # STEP 4 — SUCCESSFUL AI BLOCK
        # -----------------------------------------------------

        if (
            action == "BLOCK"
            and success
        ):

            print()
            print(
                "[DECISION ENGINE] "
                "AI authorized a successful block."
            )

            self.attack_memory.record(
                event=event,
                action="AI_BLOCK",
                duration=duration,
                reason=reason,
                enforce_on_repeat=True
            )

        # -----------------------------------------------------
        # STEP 5 — LOG ONLY
        # -----------------------------------------------------

        else:

            print()
            print(
                "[DECISION ENGINE] "
                "No firewall block stored."
            )

            self.attack_memory.record(
                event=event,
                action=action,
                duration=duration,
                reason=reason,
                enforce_on_repeat=False
            )

        return result
