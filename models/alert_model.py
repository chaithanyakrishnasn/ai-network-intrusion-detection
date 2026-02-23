from dataclasses import dataclass, field
import time


@dataclass
class Alert:
    alert_type: str
    src_ip: str
    dst_ip: str
    severity: str
    metadata: dict
    timestamp: float = field(default_factory=time.time)
