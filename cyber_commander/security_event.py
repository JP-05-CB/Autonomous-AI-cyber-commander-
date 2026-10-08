
from dataclasses import dataclass, asdict, field
import json
import time


@dataclass
class SecurityEvent:

    # ========================================================
    # Basic Event Information
    # ========================================================

    event_type: str
    source_ip: str
    target_ip: str

    # ========================================================
    # Attack-specific Information
    # ========================================================

    unique_ports: int = 0
    connection_count: int = 0

    service_port: int = 0
    failed_attempts: int = 0

    window_seconds: float = 0.0
    confidence: float = 0.0

    # ========================================================
    # Event Timestamp
    # ========================================================

    timestamp: float = field(
        default_factory=time.time
    )

    # ========================================================
    # Convert Event to Dictionary
    # ========================================================

    def to_dict(self):

        return asdict(self)

    # ========================================================
    # Convert Event to JSON
    # ========================================================

    def to_json(self):

        return json.dumps(
            self.to_dict(),
            indent=4
        )


