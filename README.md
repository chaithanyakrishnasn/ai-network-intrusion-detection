🛡️ AI-Powered Network Intrusion Detection System (AI-NIDS)

A real-time, modular Network Intrusion Detection Engine built in Python that combines:

Rule-based detection

Behavioral anomaly detection using Machine Learning

Live packet capture

Stateful flow modeling

REST + WebSocket APIs

Real-time monitoring dashboard

Designed to simulate production-grade detection systems used in modern SOC environments.

🚀 Features
🔹 Real-Time Packet Capture

Live traffic capture using Scapy

IP/TCP/UDP protocol parsing

Windows-compatible via Npcap

🔹 Stateful Flow Tracking

Bidirectional flow aggregation

Packet count, byte count, duration

TCP flag tracking (SYN/ACK/FIN/RST)

Flow rate metrics (pps, bps)

🔹 Rule-Based Detection

Port scan detection

Suspicious connection rate detection

Flow anomaly thresholds

Alert deduplication logic

🔹 Machine Learning Anomaly Detection

Isolation Forest (unsupervised)

Feature scaling (StandardScaler)

Sliding window training (500 samples)

Periodic retraining

Severity scoring based on anomaly score

🔹 Real-Time Alert System

Structured alert model

Severity levels (LOW / MEDIUM / HIGH)

REST API access

WebSocket streaming

Alert metrics aggregation

🔹 Monitoring Dashboard

Live alert feed

Packet & flow metrics chart

ML model status panel

Responsive SOC-style interface
