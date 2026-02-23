from scapy.all import sniff, IP, TCP, UDP
from models.packet_model import PacketInfo
from processing.flow_tracker import FlowTracker
from detection.rule_engine import RuleEngine
from detection.anomaly_engine import AnomalyEngine
from processing.feature_extractor import FeatureExtractor
from storage.alert_manager import AlertManager
from models.alert_model import Alert

import time
import threading


class PacketSniffer:

    def __init__(self, interface=None):
        self.interface = interface
        self.packet_count = 0
        self.start_time = time.time()
        self.lock = threading.Lock()

        # Core engines
        self.flow_tracker = FlowTracker()
        self.rule_engine = RuleEngine(self.flow_tracker)
        self.anomaly_engine = AnomalyEngine()
        self.alert_manager = AlertManager()

    # -----------------------------
    # Packet Normalization Layer
    # -----------------------------
    def _process_packet(self, packet):
        if IP not in packet:
            return None

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = None
        src_port = None
        dst_port = None
        tcp_flags = None

        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            raw_flags = packet[TCP].flags
            tcp_flags = {
                "S": int(raw_flags & 0x02 != 0),
                "A": int(raw_flags & 0x10 != 0),
                "F": int(raw_flags & 0x01 != 0),
                "R": int(raw_flags & 0x04 != 0),
            }

        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        return PacketInfo(
            timestamp=time.time(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            packet_size=len(packet),
            tcp_flags=tcp_flags
        )

    # -----------------------------
    # Packet Handler
    # -----------------------------
    def _handle_packet(self, packet):
        packet_info = self._process_packet(packet)
        if packet_info:
            with self.lock:
                self.packet_count += 1

            self.flow_tracker.process_packet(packet_info)

    # -----------------------------
    # Stats Printer
    # -----------------------------
    def _print_stats(self):
        while True:
            time.sleep(5)
            with self.lock:
                elapsed = time.time() - self.start_time
                rate = self.packet_count / elapsed if elapsed > 0 else 0

                print(
                    f"Packets: {self.packet_count} | "
                    f"Avg Rate: {rate:.2f} pkt/sec | "
                    f"Active Flows: {len(self.flow_tracker.flows)}"
                )

    # -----------------------------
    # Detection + ML Loop
    # -----------------------------
    def _run_detection(self):
        while True:
            time.sleep(5)

            flows = list(self.flow_tracker.flows.values())

            # -------------------------
            # Collect ML Samples
            # -------------------------
            for flow in flows:
                vector = FeatureExtractor.flow_to_vector(flow)
                self.anomaly_engine.add_sample(vector)

            # Retrain periodically
            if self.anomaly_engine.should_retrain():
                self.anomaly_engine.train()

            # -------------------------
            # ML Scoring
            # -------------------------
            for flow in flows:

                # Ignore short-lived flows
                if flow.duration < 8:
                    continue

                # Ignore multicast traffic
                if flow.dst_ip.startswith("224.") or flow.dst_ip.startswith("239."):
                    continue

                vector = FeatureExtractor.flow_to_vector(flow)
                result = self.anomaly_engine.score(vector)

                if not result:
                    continue

                prediction, score = result

                if prediction != -1:
                    continue

                # Ignore weak anomalies
                if score > -0.08:
                    continue

                # Severity mapping
                if score < -0.20:
                    severity = "HIGH"
                elif score < -0.10:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"

                alert_key = f"ML:{flow.src_ip}:{flow.dst_ip}"

                if self.rule_engine._should_alert(alert_key, cooldown=60):

                    alert = Alert(
                        alert_type="ML_ANOMALY_DETECTED",
                        src_ip=flow.src_ip,
                        dst_ip=flow.dst_ip,
                        severity=severity,
                        metadata={
                            "anomaly_score": round(float(score), 4),
                            "packet_count": flow.packet_count,
                            "duration": round(flow.duration, 2)
                        }
                    )

                    self.alert_manager.add_alert(alert)

                    print(
                        f"[ML ALERT] {alert.alert_type} | "
                        f"{alert.src_ip} -> {alert.dst_ip} | "
                        f"Severity: {alert.severity} | "
                        f"Score: {score:.4f}"
                    )

            # -------------------------
            # Rule-Based Detection
            # -------------------------
            alerts = self.rule_engine.analyze_flows()

            for alert in alerts:
                self.alert_manager.add_alert(alert)

                print(
                    f"[ALERT] {alert.alert_type} | "
                    f"{alert.src_ip} -> {alert.dst_ip} | "
                    f"Severity: {alert.severity}"
                )

    # -----------------------------
    # API Getter
    # -----------------------------
    def get_alerts(self):
        return self.alert_manager.get_alerts()

    # -----------------------------
    # Start Engine
    # -----------------------------
    def start(self):
        print(f"Starting structured packet capture on {self.interface}...")

        stats_thread = threading.Thread(
            target=self._print_stats,
            daemon=True
        )
        stats_thread.start()

        cleanup_thread = threading.Thread(
            target=self.flow_tracker.cleanup_expired_flows,
            daemon=True
        )
        cleanup_thread.start()

        detection_thread = threading.Thread(
            target=self._run_detection,
            daemon=True
        )
        detection_thread.start()

        sniff(
            iface=self.interface,
            filter="ip and (tcp or udp)",
            prn=self._handle_packet,
            store=False
        )
