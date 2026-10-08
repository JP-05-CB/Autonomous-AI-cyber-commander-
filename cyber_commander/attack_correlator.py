
import time
from collections import defaultdict, deque


# ============================================================
# Configuration
# ============================================================

CORRELATION_WINDOW = 30

MIN_EVENTS_FOR_CORRELATION = 2


# ============================================================
# Attack Correlator
# ============================================================

class AttackCorrelator:

    def __init__(self):

        # ----------------------------------------------------
        # Store events by source IP
        # ----------------------------------------------------

        self.event_history = defaultdict(deque)

    # ========================================================
    # Add Security Event
    # ========================================================

    def add_event(self, event):

        current_time = time.time()

        source_ip = event.source_ip

        history = self.event_history[source_ip]

        # ----------------------------------------------------
        # Remove events outside correlation window
        # ----------------------------------------------------

        while history and (
            current_time - history[0].timestamp
            > CORRELATION_WINDOW
        ):
            history.popleft()

        # ----------------------------------------------------
        # Add current event
        # ----------------------------------------------------

        history.append(event)

        # ----------------------------------------------------
        # Analyze source
        # ----------------------------------------------------

        return self.analyze(source_ip)

    # ========================================================
    # Analyze Event History
    # ========================================================

    def analyze(self, source_ip):

        history = self.event_history[source_ip]

        if len(history) < MIN_EVENTS_FOR_CORRELATION:

            return None

        # ----------------------------------------------------
        # Extract event types
        # ----------------------------------------------------

        event_types = [
            event.event_type
            for event in history
        ]

        unique_events = set(event_types)

        # ----------------------------------------------------
        # Calculate correlation score
        # ----------------------------------------------------

        score = 0

        if "PORT_SCAN" in unique_events:
            score += 1

        if "BRUTE_FORCE" in unique_events:
            score += 1

        if "HTTP_FLOOD" in unique_events:
            score += 1

        if "SYN_FLOOD" in unique_events:
            score += 1

        if "ICMP_FLOOD" in unique_events:
            score += 1

        if "ARP_SPOOFING" in unique_events:
            score += 1

        # ----------------------------------------------------
        # No meaningful correlation
        # ----------------------------------------------------

        if score < 2:

            return None

        # ----------------------------------------------------
        # Calculate average confidence
        # ----------------------------------------------------

        average_confidence = sum(
            event.confidence
            for event in history
        ) / len(history)

        # ----------------------------------------------------
        # Create correlation result
        # ----------------------------------------------------

        result = {

            "source_ip": source_ip,

            "event_count": len(history),

            "attack_types": list(unique_events),

            "correlation_score": score,

            "average_confidence": average_confidence,

            "window_seconds": CORRELATION_WINDOW
        }

        return result

    # ========================================================
    # Display Correlation
    # ========================================================

    def print_correlation(self, result):

        if result is None:

            return

        print("\n" + "=" * 60)
        print("[ATTACK CORRELATION]")
        print("=" * 60)

        print(
            f"Source IP          : "
            f"{result['source_ip']}"
        )

        print(
            f"Events observed    : "
            f"{result['event_count']}"
        )

        print(
            f"Attack types       : "
            f"{result['attack_types']}"
        )

        print(
            f"Correlation score  : "
            f"{result['correlation_score']}"
        )

        print(
            f"Average confidence : "
            f"{result['average_confidence']:.2f}"
        )

        print(
            f"Time window        : "
            f"{result['window_seconds']} seconds"
        )

        print("=" * 60)


