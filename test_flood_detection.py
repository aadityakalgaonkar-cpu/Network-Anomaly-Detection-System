from service import packet
import time

# Clear old data
packet.packet_history.clear()
packet.alerts.clear()
packet.active_alerts.clear()

# Create 110 fake packets within the last 10 seconds
for i in range(1100):

    packet.packet_history.append({
        "timestamp": time.time(),
        "source_ip": "10.10.10.20",
        "destination_ip": "192.168.1.6",
        "protocol": "TCP",
        "source_port": 40000 + i,
        "destination_port": 80,
        "packet_size": 60,
        "direction": "INCOMING",
        "source_mac": "-",
        "destination_mac": "-",
        "tcp_flags": "S"
    })

print("\nTesting flood detection...\n")

packet.detect_flood()