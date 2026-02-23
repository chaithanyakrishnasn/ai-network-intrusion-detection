from models.flow_model import Flow
from models.packet_model import PacketInfo
import threading
import time


class FlowTracker:

    def __init__(self, flow_timeout=60):
        self.flows = {}
        self.flow_timeout = flow_timeout
        self.lock = threading.Lock()

    def _generate_flow_key(self, packet: PacketInfo):
        # Bidirectional flow key
        endpoints = sorted([
            (packet.src_ip, packet.src_port),
            (packet.dst_ip, packet.dst_port)
        ])
        return (endpoints[0], endpoints[1], packet.protocol)

    def process_packet(self, packet: PacketInfo):
        key = self._generate_flow_key(packet)

        with self.lock:
            if key not in self.flows:
                self.flows[key] = Flow(
                    src_ip=packet.src_ip,
                    src_port=packet.src_port,
                    dst_ip=packet.dst_ip,
                    dst_port=packet.dst_port,
                    protocol=packet.protocol
                )

            flow = self.flows[key]

            # Determine direction (forward or backward)
            if (packet.src_ip, packet.src_port) == (flow.src_ip, flow.src_port):
                direction = "forward"
            else:
                direction = "backward"

            # For now, no TCP flag extraction
            flow.update(
                packet_size=packet.packet_size,
                direction=direction,
                flags=packet.tcp_flags
            )

    def cleanup_expired_flows(self):
        while True:
            time.sleep(10)
            now = time.time()

            with self.lock:
                expired = [
                    key for key, flow in self.flows.items()
                    if now - flow.last_seen > self.flow_timeout
                ]

                for key in expired:
                    del self.flows[key]
