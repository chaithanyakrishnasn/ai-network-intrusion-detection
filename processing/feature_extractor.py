import numpy as np


class FeatureExtractor:

    @staticmethod
    def flow_to_vector(flow):
        return np.array([
            flow.packet_count,
            flow.byte_count,
            flow.duration,
            flow.packets_per_second,
            flow.bytes_per_second,
            flow.syn_count,
            flow.ack_count,
            flow.fin_count,
            flow.rst_count,
            flow.forward_packets,
            flow.backward_packets
        ])
