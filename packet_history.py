from service import packet
import time

packet.packet_history.clear()

for i in range(5):
    packet.packet_history.append({
        "timestamp": time.time(),
        "source_ip": "10.10.10.50",
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

packet.collect_baseline_sample()