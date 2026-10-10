from service import packet
import time

packet.packet_history.clear()
packet.alerts.clear()
packet.active_alerts.clear()

for i in range(30):

    packet.packet_history.append({
        "timestamp": time.time(),
        "source_ip": "10.10.10.60",
        "destination_ip": "192.168.1.6",
        "protocol": "TCP",
        "source_port": 40000 + i,
        "destination_port": 22,
        "packet_size": 60,
        "direction": "INCOMING",
        "source_mac": "-",
        "destination_mac": "-",
        "tcp_flags": "S"
    })

print("\nTesting connection burst detection...\n")

packet.detect_connection_burst()