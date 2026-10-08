from google import genai
from google.genai import types


class CyberDefenseAgent:

    """
    Gemini-powered defensive AI agent.

    Gemini does not directly access the firewall.

    Instead:

        Gemini
           ↓
        function call
           ↓
        validation
           ↓
        FirewallTools
           ↓
        FirewallManager
    """

    def __init__(self, firewall_tools):

        self.client = genai.Client()

        self.firewall_tools = firewall_tools

        # Gemini 3.6 Flash is currently the model that
        # successfully responded in our environment.
        self.model = "gemini-3.6-flash"

        print(
            "[+] CyberDefenseAgent initialized."
        )

    # ========================================================
    # ANALYZE SECURITY EVENT
    # ========================================================

    def analyze_event(
        self,
        event,
        correlation=None
    ):

        print()
        print("=" * 60)
        print("[GEMINI AGENT] ANALYZING SECURITY EVENT")
        print("=" * 60)

        print(
            f"Attack type : {event.event_type}"
        )

        print(
            f"Source IP   : {event.source_ip}"
        )

        print(
            f"Confidence  : {event.confidence}"
        )

        prompt = self._build_prompt(
            event,
            correlation
        )

        # ====================================================
        # FUNCTION DECLARATION
        # ====================================================

        block_ip_function = {
            "name": "block_ip",

            "description": (
                "Block a malicious source IPv4 address "
                "using the defensive eBPF/XDP firewall."
            ),

            "parameters": {

                "type": "object",

                "properties": {

                    "ip": {

                        "type": "string",

                        "description": (
                            "IPv4 address of the malicious "
                            "source."
                        )
                    },

                    "duration": {

                        "type": "integer",

                        "description": (
                            "Number of seconds to block "
                            "the source IP. Maximum 3600."
                        )
                    },

                    "reason": {

                        "type": "string",

                        "description": (
                            "Security reason for blocking "
                            "the source IP."
                        )
                    }
                },

                "required": [
                    "ip",
                    "duration",
                    "reason"
                ]
            }
        }

        # ====================================================
        # CREATE GEMINI CHAT
        # ====================================================

        chat = self.client.chats.create(

            model=self.model,

            config=types.GenerateContentConfig(

                tools=[
                    {
                        "function_declarations": [
                            block_ip_function
                        ]
                    }
                ]
            )
        )

        # ====================================================
        # SEND EVENT TO GEMINI
        # ====================================================

        response = chat.send_message(
            prompt
        )

        # ====================================================
        # CHECK FUNCTION CALL
        # ====================================================

        if response.function_calls:

            for function_call in response.function_calls:

                print()
                print("=" * 60)
                print(
                    "[GEMINI AGENT] "
                    "FUNCTION CALL REQUESTED"
                )
                print("=" * 60)

                print(
                    f"Function : "
                    f"{function_call.name}"
                )

                print(
                    f"Arguments: "
                    f"{function_call.args}"
                )

                # =================================================
                # ONLY ALLOW block_ip
                # =================================================

                if function_call.name != "block_ip":

                    print(
                        "[SECURITY] "
                        "Unknown function rejected."
                    )

                    return {
                        "success": False,
                        "action": "LOG_ONLY",
                        "reason": (
                            "Unknown function requested."
                        )
                    }

                args = function_call.args

                ip = args.get(
                    "ip"
                )

                duration = args.get(
                    "duration"
                )

                reason = args.get(
                    "reason"
                )

                # =================================================
                # SECURITY VALIDATION
                # =================================================

                # -------------------------------------------------
                # Validate IP
                # -------------------------------------------------

                if ip != event.source_ip:

                    print(
                        "[SECURITY] "
                        "BLOCK REJECTED"
                    )

                    print(
                        "[SECURITY] Gemini attempted "
                        "to block an IP different "
                        "from the event source."
                    )

                    return {
                        "success": False,
                        "action": "LOG_ONLY",
                        "reason": (
                            "Source IP validation failed."
                        )
                    }

                # -------------------------------------------------
                # Validate duration
                # -------------------------------------------------

                if not isinstance(
                    duration,
                    int
                ):

                    print(
                        "[SECURITY] "
                        "BLOCK REJECTED"
                    )

                    return {
                        "success": False,
                        "action": "LOG_ONLY",
                        "reason": (
                            "Invalid block duration."
                        )
                    }

                if duration <= 0:

                    print(
                        "[SECURITY] "
                        "BLOCK REJECTED"
                    )

                    return {
                        "success": False,
                        "action": "LOG_ONLY",
                        "reason": (
                            "Block duration must "
                            "be greater than zero."
                        )
                    }

                # -------------------------------------------------
                # Enforce maximum duration
                # -------------------------------------------------

                if duration > 3600:

                    print(
                        "[SECURITY] "
                        "Duration exceeds maximum."
                    )

                    print(
                        "[SECURITY] "
                        "Capping duration at 3600 seconds."
                    )

                    duration = 3600

                # =================================================
                # EXECUTE CONTROLLED FIREWALL TOOL
                # =================================================

                result = (
                    self.firewall_tools.block_ip(

                        ip=ip,

                        duration=duration,

                        reason=reason
                    )
                )

                print()
                print(
                    "[FIREWALL TOOL RESULT]"
                )

                print(result)

                # =================================================
                # SEND TOOL RESULT BACK TO GEMINI
                # =================================================

                final_response = chat.send_message(

                    types.Part.from_function_response(

                        name=function_call.name,

                        response=result
                    )
                )

                print()
                print(
                    "[GEMINI AGENT] Final response:"
                )

                print(
                    final_response.text
                )

                # =================================================
                # RETURN STRUCTURED RESULT
                # =================================================

                return {

                    "success":
                        result.get(
                            "success",
                            False
                        ),

                    "action":
                        "BLOCK"
                        if result.get(
                            "success",
                            False
                        )
                        else "LOG_ONLY",

                    "ip":
                        ip,

                    "duration":
                        duration,

                    "reason":
                        reason,

                    "ai_response":
                        final_response.text
                }

        # ====================================================
        # NO FIREWALL ACTION
        # ====================================================

        print()
        print(
            "[GEMINI AGENT] "
            "No firewall action requested."
        )

        print(
            "[GEMINI AGENT] Response:"
        )

        print(
            response.text
        )

        return {

            "success": True,

            "action": "LOG_ONLY",

            "ip":
                event.source_ip,

            "duration":
                None,

            "reason":
                "Gemini did not request a firewall action.",

            "ai_response":
                response.text
        }

    # ========================================================
    # BUILD GEMINI PROMPT
    # ========================================================

    def _build_prompt(
        self,
        event,
        correlation=None
    ):

        if correlation:

            correlation_text = str(
                correlation
            )

        else:

            correlation_text = (
                "No correlation information."
            )

        evidence = getattr(
            event,
            "evidence",
            {}
        )

        return f"""
You are the defensive AI decision agent of
Autonomous AI Cyber Commander.

You operate only inside an authorized cybersecurity
laboratory environment.

Your responsibility is to analyze detected security
events and determine whether defensive firewall
action is required.

AVAILABLE TOOL:

block_ip(ip, duration, reason)

SECURITY RULES:

1. Only block the source IP associated with the event.

2. Never invent an IP address.

3. Never block the target IP.

4. Never execute shell commands.

5. Never generate executable code.

6. Never modify the firewall directly.

7. Use the block_ip function when blocking is justified.

8. Confidence below 0.70 normally requires monitoring.

9. High-confidence malicious events normally require
   defensive blocking.

10. Correlated attacks should receive stronger
    consideration.

11. Block duration must be between 1 and 3600 seconds.

12. If blocking is justified, provide a concise reason.

SECURITY EVENT:

Attack type:
{event.event_type}

Source IP:
{event.source_ip}

Target IP:
{event.target_ip}

Confidence:
{event.confidence}

Evidence:
{evidence}

Correlation:
{correlation_text}

Analyze the event and determine the appropriate
defensive action.
"""
