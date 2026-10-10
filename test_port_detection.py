from service import packet
import time

# Clear old packet history and alerts
packet.packet_history.clear()
packet.alerts.clear()
packet.active_alerts.clear()

# Create 12 fake incoming packets from one source IP
for port in range(5001, 5013):

    packet.packet_history.append({
        "timestamp": time.time(),
        "source_ip": "10.10.10.10",
        "destination_ip": "192.168.1.6",
        "protocol": "TCP",
        "source_port": 40000 + port,
        "destination_port": port,
        "packet_size": 60,
        "direction": "INCOMING",
        "source_mac": "-",
        "destination_mac": "-",
        "tcp_flags": "S"
    })

print("\nTesting port scan detection...\n")

packet.detect_port_scan_rolling()