import json
import os
import threading
from datetime import datetime


class AttackMemory:

    def __init__(self, filename="attack_history.json"):
        self.filename = filename
        self.lock = threading.Lock()
        self.history = {}

        self._load()

        print("=" * 60)
        print("CYBER COMMANDER - ATTACK MEMORY")
        print("=" * 60)
        print(f"Memory file : {self.filename}")
        print(f"Known attacks : {len(self.history)}")
        print("=" * 60)

    # ---------------------------------------------------------
    # LOAD MEMORY
    # ---------------------------------------------------------

    def _load(self):

        if not os.path.exists(self.filename):
            self.history = {}
            return

        try:

            with open(self.filename, "r") as f:
                self.history = json.load(f)

            print(
                f"[ATTACK MEMORY] Loaded "
                f"{len(self.history)} stored records."
            )

        except Exception as e:

            print(
                f"[ATTACK MEMORY] Failed to load memory: {e}"
            )

            self.history = {}

    # ---------------------------------------------------------
    # SAVE MEMORY
    # ---------------------------------------------------------

    def _save(self):

        temp_file = self.filename + ".tmp"

        with open(temp_file, "w") as f:
            json.dump(
                self.history,
                f,
                indent=4
            )

        os.replace(
            temp_file,
            self.filename
        )

    # ---------------------------------------------------------
    # GENERATE KEY
    # ---------------------------------------------------------

    @staticmethod
    def _make_key(source_ip, event_type):

        return f"{source_ip}|{event_type}"

    # ---------------------------------------------------------
    # LOOKUP ONLY KNOWN MALICIOUS ATTACKS
    # ---------------------------------------------------------

    def lookup(self, source_ip, event_type):

        key = self._make_key(
            source_ip,
            event_type
        )

        with self.lock:

            record = self.history.get(key)

            if not record:
                return None

            # IMPORTANT:
            # Only attacks that were previously blocked
            # are considered known attacks.

            if not record.get(
                "enforce_on_repeat",
                False
            ):
                return None

            return record.copy()

    # ---------------------------------------------------------
    # RECORD ATTACK
    # ---------------------------------------------------------

    def record(
        self,
        event,
        action,
        duration=None,
        reason=None,
        enforce_on_repeat=False
    ):

        key = self._make_key(
            event.source_ip,
            event.event_type
        )

        now = datetime.now().isoformat()

        with self.lock:

            if key not in self.history:

                self.history[key] = {

                    "source_ip":
                        event.source_ip,

                    "event_type":
                        event.event_type,

                    "first_seen":
                        now,

                    "last_seen":
                        now,

                    "count":
                        0,

                    "last_action":
                        action,

                    "duration":
                        duration,

                    "reason":
                        reason,

                    "enforce_on_repeat":
                        enforce_on_repeat
                }

            record = self.history[key]

            record["last_seen"] = now

            record["count"] += 1

            record["last_action"] = action

            record["duration"] = duration

            record["reason"] = reason

            # Once an attack has been successfully blocked,
            # it remains eligible for immediate blocking.

            if enforce_on_repeat:
                record["enforce_on_repeat"] = True

            self._save()

        print()
        print("[ATTACK MEMORY] Record updated")
        print("-" * 60)
        print(f"Source IP          : {event.source_ip}")
        print(f"Attack type        : {event.event_type}")
        print(f"Action             : {action}")
        print(f"Count              : {record['count']}")
        print(
            f"Immediate repeat   : "
            f"{record['enforce_on_repeat']}"
        )
        print("-" * 60)

    # ---------------------------------------------------------
    # DISPLAY MEMORY
    # ---------------------------------------------------------

    def display_history(self):

        print()
        print("=" * 70)
        print("                 ATTACK HISTORY")
        print("=" * 70)

        if not self.history:

            print("No stored attacks.")

            print("=" * 70)

            return

        for key, record in self.history.items():

            print()
            print(f"Key               : {key}")
            print(
                f"First seen        : "
                f"{record.get('first_seen')}"
            )
            print(
                f"Last seen         : "
                f"{record.get('last_seen')}"
            )
            print(
                f"Occurrences       : "
                f"{record.get('count')}"
            )
            print(
                f"Last action       : "
                f"{record.get('last_action')}"
            )
            print(
                f"Duration          : "
                f"{record.get('duration')}"
            )
            print(
                f"Enforce repeat    : "
                f"{record.get('enforce_on_repeat')}"
            )
            print(
                f"Reason            : "
                f"{record.get('reason')}"
            )

        print()
        print("=" * 70)
