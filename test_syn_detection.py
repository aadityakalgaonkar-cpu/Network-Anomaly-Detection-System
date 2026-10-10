from service import packet
import time

# Clear old data
packet.tcp_flows.clear()
packet.alerts.clear()
packet.active_alerts.clear()

# Create 600 incomplete incoming TCP SYN flows
for i in range(600):

    flow = (
        "10.10.10.30",       # external source
        40000 + i,            # source port
        "192.168.1.6",        # our machine
        80                    # destination port
    )

    packet.tcp_flows[flow] = {
        "syn": True,
        "syn_ack": False,
        "ack": False,
        "timestamp": time.time()
    }

print("\nTesting SYN flood detection...\n")

packet.detect_syn_flood()