from scapy.all import IP, TCP, send
import time

target = "192.168.1.6"
fake_source = "10.10.10.10"

ports = [
    5001, 5002, 5003, 5004,
    5005, 5006, 5007, 5008,
    5009, 5010, 5011, 5012
]

for port in ports:
    packet = IP(src=fake_source, dst=target) / TCP(
        sport=40000 + port,
        dport=port,
        flags="S"
    )

    send(packet, verbose=False)
    print("Sent SYN to port", port)
    time.sleep(0.2)