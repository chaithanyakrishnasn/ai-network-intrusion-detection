from models.alert_model import Alert
import time


class RuleEngine:

    def __init__(self, flow_tracker):
        self.flow_tracker = flow_tracker
        self.alert_cache = {}  # for deduplication

    def _should_alert(self, key, cooldown=30):
        now = time.time()

        if key not in self.alert_cache:
            self.alert_cache[key] = now
            return True

        if now - self.alert_cache[key] > cooldown:
            self.alert_cache[key] = now
            return True

        return False

    def analyze_flows(self):
        alerts = []
        flows = list(self.flow_tracker.flows.values())

        # ----------------------------
        # SYN Flood Detection
        # ----------------------------
        for flow in flows:

            if flow.protocol != "TCP":
                continue

            if flow.duration < 3:
                continue

            syn_rate = flow.syn_count / flow.duration if flow.duration > 0 else 0
            ack_ratio = (
                flow.ack_count / flow.syn_count
                if flow.syn_count > 0 else 1
            )

            if syn_rate > 5 and ack_ratio < 0.2:

                key = f"SYN:{flow.src_ip}:{flow.dst_ip}"

                if self._should_alert(key):

                    alerts.append(Alert(
                        alert_type="SYN_FLOOD_SUSPECTED",
                        src_ip=flow.src_ip,
                        dst_ip=flow.dst_ip,
                        severity="HIGH",
                        metadata={
                            "syn_rate": round(syn_rate, 2),
                            "ack_ratio": round(ack_ratio, 2),
                        }
                    ))

        # ----------------------------
        # Port Scan Detection
        # ----------------------------
        src_to_ports = {}

        for flow in flows:
            key = (flow.src_ip, flow.dst_ip)

            if key not in src_to_ports:
                src_to_ports[key] = set()

            src_to_ports[key].add(flow.dst_port)

        for (src_ip, dst_ip), ports in src_to_ports.items():
            if len(ports) > 15:

                key = f"SCAN:{src_ip}:{dst_ip}"

                if self._should_alert(key):

                    alerts.append(Alert(
                        alert_type="PORT_SCAN_SUSPECTED",
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        severity="MEDIUM",
                        metadata={
                            "unique_ports": len(ports)
                        }
                    ))

        return alerts
