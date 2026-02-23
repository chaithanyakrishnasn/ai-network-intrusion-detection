from dataclasses import dataclass
from typing import Optional, Dict


@dataclass
class PacketInfo:
    timestamp: float
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: Optional[str]
    packet_size: int
    tcp_flags: Optional[Dict[str, int]] = None
