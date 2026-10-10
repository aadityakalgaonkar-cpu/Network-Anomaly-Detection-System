from service import packet
import time

packet.packet_history.clear()
packet.alerts.clear()
packet.active_alerts.clear()

for i in range(1100):

    packet.packet_history.append({
        "timestamp": time.time(),
        "source_ip": "10.10.10.50",
        "destination_ip": "192.168.1.6",
        "protocol": "ICMP",
        "source_port": "-",
        "destination_port": "-",
        "packet_size": 60,
        "direction": "INCOMING",
        "source_mac": "-",
        "destination_mac": "-",
        "tcp_flags": ""
    })

print("\nTesting ICMP flood detection...\n")

packet.detect_icmp_flood()