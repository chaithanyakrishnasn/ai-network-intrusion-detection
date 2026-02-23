from dataclasses import dataclass, field
import time


@dataclass
class Flow:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str

    start_time: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    packet_count: int = 0
    byte_count: int = 0

    # Directional tracking
    forward_packets: int = 0
    backward_packets: int = 0

    # TCP flag tracking
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0

    def update(self, packet_size: int, direction: str, flags: dict = None):
        self.packet_count += 1
        self.byte_count += packet_size
        self.last_seen = time.time()

        if direction == "forward":
            self.forward_packets += 1
        else:
            self.backward_packets += 1

        if flags:
            self.syn_count += flags.get("S", 0)
            self.ack_count += flags.get("A", 0)
            self.fin_count += flags.get("F", 0)
            self.rst_count += flags.get("R", 0)

    @property
    def duration(self):
        return self.last_seen - self.start_time

    @property
    def packets_per_second(self):
        return self.packet_count / self.duration if self.duration > 0 else 0

    @property
    def bytes_per_second(self):
        return self.byte_count / self.duration if self.duration > 0 else 0
