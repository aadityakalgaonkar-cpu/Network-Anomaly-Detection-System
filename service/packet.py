#import this to send the data to consumer
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

#importing local address from network utils
from network_utils import get_local_ips

#connectiong packet to djangos database we created 
import os
import sys
import django
import atexit

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

sys.path.insert(0, PROJECT_ROOT)

os.environ.setdefault(
    "DJANGO_SETTINGS_MODULE",
    "packetcollectors.settings"
)

django.setup()

#importing model tables
from service.models import FixedRuleAlert, Baseline, BaselineAlert, NIDSSession, AllPacket
from datetime import datetime
from django.utils import timezone

from scapy.all import sniff, IP, IPv6, TCP, UDP, Ether, ICMP
from collections import defaultdict, deque
import time
import socket

my_ips=get_local_ips()

alerts = []
active_alerts = {}
packet_history = deque()
tcp_flows = {}
nids_session=None
source_last_seen = {}
packet_number=0

def stop_nids_session():

    global nids_session

    if nids_session is not None:

        if nids_session.stopped_at is None:

            nids_session.stopped_at = timezone.now()
            nids_session.save()

            print("\nNIDS Session Stopped")
            print("Session ID:", nids_session.id)

atexit.register(stop_nids_session)

session_stats = {
    "total_packets": 0,
    "total_bytes": 0,
    "unique_source_ips": set(),
    "unique_destination_ips": set(),
    "total_tcp": 0,
    "total_syn": 0,
    "total_udp": 0,
    "total_icmp": 0,
    "total_other": 0,
    "total_incoming": 0,
    "total_outgoing": 0,
    "total_local": 0,
    "total_other_direction": 0
}

# Stores 10 second traffic samples for baseline learning
baseline_history = defaultdict(lambda: {
    "samples": [],
    "learning": True,
    "status": "LEARNING",
    "activity": "INACTIVE",
    "first_seen": None,
    "last_seen": None,
    "baseline": None
})

baseline_start_time = time.time()
baseline_learning_duration = 180
baseline_ready = False

traffic=defaultdict(lambda:{"packet_count":0,
                            "total_bytes":0,
                            "total_protocols":defaultdict(int),
                            "total_ports":defaultdict(int),
                            "incoming_ports":defaultdict(int),
                            "total_desip":defaultdict(int),
                            "directions":defaultdict(int),
                            "source_macs":defaultdict(int),
                            "destination_macs":defaultdict(int),
                            })

def packet_received(packet):

    global session_stats
    global packet_number
    packet_number+=1

    # IPv4 packet
    if IP in packet:
        inpc="IPv4"
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

    # IPv6 packet
    elif IPv6 in packet:
        inpc="IPv6"
        source_ip = packet[IPv6].src
        destination_ip = packet[IPv6].dst

    else:
        return

    source_last_seen[source_ip] = time.time()

    #tracking the mac address 
    if Ether in packet:
        source_mac=packet[Ether].src
        destination_mac=packet[Ether].dst

    else:
        source_mac="-"
        destination_mac="-"

    # Protocol and ports

    # Track TCP connection state
    if TCP in packet:
        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport
        tcp_flags = str(packet[TCP].flags)

    elif UDP in packet:
        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport
        tcp_flags = ""

    elif ICMP in packet:
        protocol = "ICMP"
        source_port = "-"
        destination_port = "-"
        tcp_flags = ""
    
    else:
        protocol = "Other"
        source_port = "-"
        destination_port = "-"
        tcp_flags = ""

    # Track TCP connection state
    if TCP in packet:

        flow = (
            source_ip,
            source_port,
            destination_ip,
            destination_port
        )

        reverse_flow = (
            destination_ip,
            destination_port,
            source_ip,
            source_port
        )

        flags = str(packet[TCP].flags)

        # New connection attempt
        if flags == "S" and destination_ip in my_ips and source_ip not in my_ips:

            tcp_flows[flow] = {
                "syn": True,
                "syn_ack": False,
                "ack": False,
                "timestamp": time.time()
            }

        # SYN-ACK response
        elif flags == "SA" and reverse_flow in tcp_flows:

            tcp_flows[reverse_flow]["syn_ack"] = True

        # Final ACK completing the handshake
        elif "A" in flags and flow in tcp_flows:

            tcp_flows[flow]["ack"] = True

    # Packet size
    packet_size = len(packet)

    #setting direction for every packet if its local outgoing incoming or other
    if source_ip in my_ips and destination_ip in my_ips:
        direction = "LOCAL"

    elif source_ip in my_ips:
        direction = "OUTGOING"

    elif destination_ip in my_ips:
        direction = "INCOMING"

    else:
        direction = "OTHER"

    AllPacket.objects.create(
        session=nids_session,
        packet_number=packet_number,
        timestamp=timezone.now(),

        source_ip=source_ip,
        destination_ip=destination_ip,

        source_mac=source_mac,
        destination_mac=destination_mac,

        protocol=protocol,

        source_port=(
            source_port
            if source_port != "-"
            else None
        ),

        destination_port=(
            destination_port
            if destination_port != "-"
            else None
        ),

        packet_size=packet_size,

        direction=direction,

        tcp_flags=tcp_flags if tcp_flags else None,

        is_tcp=(protocol == "TCP"),
        is_udp=(protocol == "UDP"),
        is_icmp=(protocol == "ICMP"),
        is_syn=(protocol == "TCP" and tcp_flags == "S")
    )

    # Update cumulative NIDS session statistics
    session_stats["total_packets"] += 1
    session_stats["total_bytes"] += packet_size

    session_stats["unique_source_ips"].add(source_ip)
    session_stats["unique_destination_ips"].add(destination_ip)

    if protocol == "TCP":
        session_stats["total_tcp"] += 1

        if tcp_flags == "S":
            session_stats["total_syn"] += 1

    elif protocol == "UDP":
        session_stats["total_udp"] += 1

    elif protocol == "ICMP":
        session_stats["total_icmp"] += 1

    else:
        session_stats["total_other"] += 1

    if direction == "INCOMING":
        session_stats["total_incoming"] += 1

    elif direction == "OUTGOING":
        session_stats["total_outgoing"] += 1

    elif direction == "LOCAL":
        session_stats["total_local"] += 1

    else:
        session_stats["total_other_direction"] += 1

    packet_history.append({
    "timestamp": time.time(),
    "source_ip": source_ip,
    "destination_ip": destination_ip,
    "protocol": protocol,
    "source_port": source_port,
    "destination_port": destination_port,
    "packet_size": packet_size,
    "direction": direction,
    "source_mac": source_mac,
    "destination_mac": destination_mac,
    "tcp_flags": tcp_flags,
    })

    #updating info
    traffic[source_ip]["packet_count"] += 1
    traffic[source_ip]["total_bytes"] += packet_size
    traffic[source_ip]["total_protocols"][protocol]+=1 
    if destination_port != "-":
        traffic[source_ip]["total_ports"][destination_port] +=1
    if direction == "INCOMING" and destination_port != "-":
        traffic[source_ip]["incoming_ports"][destination_port]+=1
    traffic[source_ip]["total_desip"][destination_ip] +=1
    traffic[source_ip]["directions"][direction] += 1
    traffic[source_ip]["source_macs"][source_mac] += 1
    traffic[source_ip]["destination_macs"][destination_mac] += 1

    cleanup_packet_history()
    cleanup_tcp_flows()

#to get the history pf packets 
def get_recent_packets(seconds):
    current_time = time.time()

    recent_packets = [
        packet for packet in packet_history
        if current_time - packet["timestamp"] <= seconds
    ]

    return recent_packets

#cleaning the history after 60 sec
def cleanup_packet_history():

    current_time = time.time()

    while packet_history:
        oldest_packet = packet_history[0]

        if current_time - oldest_packet["timestamp"] > 60:
            packet_history.popleft()
        else:
            break

#cleaning the tcp history after 60 sec
def cleanup_tcp_flows():

    current_time = time.time()

    expired_flows = []

    for flow, data in tcp_flows.items():

        if current_time - data["timestamp"] > 60:
            expired_flows.append(flow)

    for flow in expired_flows:
        del tcp_flows[flow]

#rolling history for packets 
def analyze_recent_traffic(seconds):

    recent_packets = get_recent_packets(seconds)

    stats = defaultdict(lambda: {
        "packet_count": 0,
        "incoming_packet_count": 0,
        "total_bytes": 0,
        "destination_ports": set(),
        "incoming_ports": set(),
        "destination_ips": set(),
        "source_macs":set(),
        "tcp_count": 0,
        "udp_count": 0,
        "icmp_count": 0,
        "syn_count": 0,
        "connection_attempts": 0,
        "connection_ports": set(),
        "connection_port_counts": defaultdict(int),
    })

    for packet in recent_packets:

        ip = packet["source_ip"]

        stats[ip]["packet_count"] += 1

        if packet["direction"] == "INCOMING":
            stats[ip]["incoming_packet_count"] += 1

        stats[ip]["total_bytes"] += packet["packet_size"]

        if packet["destination_port"] != "-":
            stats[ip]["destination_ports"].add(
                packet["destination_port"]
            )

        if (
            packet["direction"] == "INCOMING"
            and packet["destination_port"] != "-"
        ):
            stats[ip]["incoming_ports"].add(
                packet["destination_port"]
            )

        stats[ip]["destination_ips"].add(
            packet["destination_ip"]
        )

        if packet["protocol"] == "TCP":
            stats[ip]["tcp_count"] += 1

            if packet["tcp_flags"] == "S" and packet["direction"] == "INCOMING":
                stats[ip]["syn_count"] += 1
                stats[ip]["connection_attempts"] += 1

                if packet["destination_port"] != "-":
                    stats[ip]["connection_ports"].add(
                        packet["destination_port"]
                    )

                stats[ip]["connection_port_counts"][packet["destination_port"]] += 1

        elif packet["protocol"] == "UDP":
            stats[ip]["udp_count"] += 1

        elif packet["protocol"] == "ICMP":
            stats[ip]["icmp_count"] += 1

        if packet["source_mac"] != "-":
            stats[ip]["source_macs"].add(packet["source_mac"])

    return stats

#creating a baseline 
def collect_baseline_sample():

    global baseline_ready

    stats = analyze_recent_traffic(10)

    current_time = time.time()

    # Process every source IP seen in the last 10 seconds
    for ip, data in stats.items():

        # We only want incoming traffic for the baseline
        if data["incoming_packet_count"] == 0:
            continue

        # Create entry if IP is seen for the first time
        if ip not in baseline_history:
            baseline_history[ip] = {
                "samples": [],
                "learning": True,
                "status": "LEARNING",
                "activity": "INACTIVE",
                "first_seen": current_time,
                "last_seen": current_time,
                "baseline": None
            }

        # Update activity information
        baseline_history[ip]["last_seen"] = current_time
        baseline_history[ip]["activity"] = "ACTIVE"

        # Don't collect more samples after baseline is created
        if baseline_history[ip]["baseline"] is not None:
            continue

        # -----------------------------------------
        # Calculate incoming traffic metrics
        # -----------------------------------------

        packets_per_sec = data["incoming_packet_count"] / 10

        incoming_bytes = 0
        incoming_tcp = 0
        incoming_udp = 0
        incoming_icmp = 0

        for packet in get_recent_packets(10):

            if (
                packet["source_ip"] == ip
                and packet["direction"] == "INCOMING"
            ):

                incoming_bytes += packet["packet_size"]

                if packet["protocol"] == "TCP":
                    incoming_tcp += 1

                elif packet["protocol"] == "UDP":
                    incoming_udp += 1

                elif packet["protocol"] == "ICMP":
                    incoming_icmp += 1

        bytes_per_sec = incoming_bytes / 10

        # -----------------------------------------
        # Create one 10-second baseline sample
        # -----------------------------------------

        sample = {
            "packets_per_sec": packets_per_sec,
            "bytes_per_sec": bytes_per_sec,
            "tcp_per_sec": incoming_tcp / 10,
            "udp_per_sec": incoming_udp / 10,
            "icmp_per_sec": incoming_icmp / 10,
            "unique_ports": len(data["incoming_ports"]),
            "unique_destination_ips": len(data["destination_ips"])
        }

        # Store sample
        baseline_history[ip]["samples"].append(sample)

        # -----------------------------------------
        # Keep only recent learning samples
        # -----------------------------------------

        if len(baseline_history[ip]["samples"]) > 30:
            baseline_history[ip]["samples"].pop(0)

    # ==================================================
    # CHECK WHETHER INITIAL LEARNING PERIOD IS COMPLETE
    # ==================================================

    if not baseline_ready:

        if current_time - baseline_start_time >= baseline_learning_duration:

            print("\n======================================")
            print(" INITIAL LEARNING PERIOD COMPLETE")
            print(" Creating traffic baselines...")
            print("======================================\n")

            for ip, data in baseline_history.items():

                samples = data["samples"]

                # Need at least 5 samples
                if len(samples) < 5:
                    continue

                # -----------------------------------------
                # Calculate average values
                # -----------------------------------------

                avg_packets = (
                    sum(s["packets_per_sec"] for s in samples)
                    / len(samples)
                )

                avg_bytes = (
                    sum(s["bytes_per_sec"] for s in samples)
                    / len(samples)
                )

                avg_tcp = (
                    sum(s["tcp_per_sec"] for s in samples)
                    / len(samples)
                )

                avg_udp = (
                    sum(s["udp_per_sec"] for s in samples)
                    / len(samples)
                )

                avg_icmp = (
                    sum(s["icmp_per_sec"] for s in samples)
                    / len(samples)
                )

                avg_ports = (
                    sum(s["unique_ports"] for s in samples)
                    / len(samples)
                )

                avg_destination_ips = (
                    sum(
                        s["unique_destination_ips"]
                        for s in samples
                    )
                    / len(samples)
                )

                # -----------------------------------------
                # Create baseline
                # -----------------------------------------

                data["baseline"] = {
                    "packets_per_sec": avg_packets,
                    "bytes_per_sec": avg_bytes,
                    "tcp_per_sec": avg_tcp,
                    "udp_per_sec": avg_udp,
                    "icmp_per_sec": avg_icmp,
                    "unique_ports": avg_ports,
                    "unique_destination_ips": avg_destination_ips
                }

                data["learning"] = False
                data["status"] = "BASELINE READY"

                Baseline.objects.create(
                    session=nids_session,
                    source_ip=ip,
                    packets_per_sec=avg_packets,
                    bytes_per_sec=avg_bytes,
                    tcp_per_sec=avg_tcp,
                    udp_per_sec=avg_udp,
                    icmp_per_sec=avg_icmp,
                    unique_ports=avg_ports,
                    unique_destination_ips=avg_destination_ips,
                    sample_count=len(samples),
                    status="BASELINE READY",
                    activity=data["activity"],
                    first_seen=datetime.fromtimestamp(
                        data["first_seen"]
                    ),
                    last_seen=datetime.fromtimestamp(
                        data["last_seen"]
                    )
                )

            baseline_ready = True

            print("Baselines created successfully.")
            print("======================================\n")

    # ==================================================
    # AFTER INITIAL LEARNING
    # CREATE BASELINE FOR NEW IPs
    # ==================================================

    else:

        for ip, data in baseline_history.items():

            # Already has baseline
            if data["baseline"] is not None:
                continue

            samples = data["samples"]

            # Need at least 5 samples
            if len(samples) < 5:
                continue

            avg_packets = (
                sum(s["packets_per_sec"] for s in samples)
                / len(samples)
            )

            avg_bytes = (
                sum(s["bytes_per_sec"] for s in samples)
                / len(samples)
            )

            avg_tcp = (
                sum(s["tcp_per_sec"] for s in samples)
                / len(samples)
            )

            avg_udp = (
                sum(s["udp_per_sec"] for s in samples)
                / len(samples)
            )

            avg_icmp = (
                sum(s["icmp_per_sec"] for s in samples)
                / len(samples)
            )

            avg_ports = (
                sum(s["unique_ports"] for s in samples)
                / len(samples)
            )

            avg_destination_ips = (
                sum(
                    s["unique_destination_ips"]
                    for s in samples
                )
                / len(samples)

            )

            data["baseline"] = {
                "packets_per_sec": avg_packets,
                "bytes_per_sec": avg_bytes,
                "tcp_per_sec": avg_tcp,
                "udp_per_sec": avg_udp,
                "icmp_per_sec": avg_icmp,
                "unique_ports": avg_ports,
                "unique_destination_ips": avg_destination_ips
            }

            data["learning"] = False
            data["status"] = "BASELINE READY"

            Baseline.objects.create(
                session=nids_session,
                source_ip=ip,
                packets_per_sec=avg_packets,
                bytes_per_sec=avg_bytes,
                tcp_per_sec=avg_tcp,
                udp_per_sec=avg_udp,
                icmp_per_sec=avg_icmp,
                unique_ports=avg_ports,
                unique_destination_ips=avg_destination_ips,
                sample_count=len(samples),
                status="BASELINE READY",
                activity=data["activity"],
                first_seen=datetime.fromtimestamp(
                    data["first_seen"]
                ),
                last_seen=datetime.fromtimestamp(
                    data["last_seen"]
                )
            )

    # ==================================================
    # UPDATE ACTIVE / INACTIVE STATUS
    # ==================================================

    for ip, data in baseline_history.items():

        if data["last_seen"] is None:
            continue

        # If IP hasn't been seen for 30 seconds
        if current_time - data["last_seen"] > 30:

            data["activity"] = "INACTIVE"

        else:

            data["activity"] = "ACTIVE"

def show_baseline():

    print("\n========== CURRENT BASELINES ==========\n")

    for ip, data in baseline_history.items():

        if data["baseline"] is None:
            continue

        baseline = data["baseline"]

        print("IP                    :", ip)
        print("Status                :", data["status"])
        print("Activity              :", data["activity"])
        print("Baseline Packets/sec  :", round(baseline["packets_per_sec"], 2))
        print("Baseline Bytes/sec    :", round(baseline["bytes_per_sec"], 2))
        print("Baseline TCP/sec      :", round(baseline["tcp_per_sec"], 2))
        print("Baseline UDP/sec      :", round(baseline["udp_per_sec"], 2))
        print("Baseline ICMP/sec     :", round(baseline["icmp_per_sec"], 2))
        print("Baseline Unique Ports :", round(baseline["unique_ports"], 2))
        print("--------------------------------------")

    print("======================================\n")

# Detect abnormal traffic by comparing current traffic with learned baseline
def detect_baseline_anomaly():
    print("\n========== BASELINE ANOMALY ANALYSIS ==========\n")

    stats = analyze_recent_traffic(10)
    current_alerts = set()

    for ip, data in stats.items():

        if ip not in baseline_history:
            continue

        baseline_data = baseline_history[ip]["baseline"]

        if baseline_data is None:
            continue

        # Current incoming packets/sec
        current_packets = data["incoming_packet_count"] / 10

        # Calculate current incoming-only metrics
        current_bytes = 0
        current_tcp = 0
        current_udp = 0
        current_icmp = 0

        for packet in get_recent_packets(10):

            if (
                packet["source_ip"] == ip
                and packet["direction"] == "INCOMING"
            ):

                current_bytes += packet["packet_size"]

                if packet["protocol"] == "TCP":
                    current_tcp += 1

                elif packet["protocol"] == "UDP":
                    current_udp += 1

                elif packet["protocol"] == "ICMP":
                    current_icmp += 1

        current_bytes = current_bytes / 10
        current_tcp = current_tcp / 10
        current_udp = current_udp / 10
        current_icmp = current_icmp / 10

        # Current unique incoming ports
        current_ports = len(data["incoming_ports"])

        # Compare current traffic with baseline
        packet_anomaly = (
            baseline_data["packets_per_sec"] > 0
            and current_packets >
            baseline_data["packets_per_sec"] * 3
        )

        byte_anomaly = (
            baseline_data["bytes_per_sec"] > 0
            and current_bytes >
            baseline_data["bytes_per_sec"] * 3
        )

        tcp_anomaly = (
            baseline_data["tcp_per_sec"] > 0
            and current_tcp >
            baseline_data["tcp_per_sec"] * 3
        )

        udp_anomaly = (
            baseline_data["udp_per_sec"] > 0
            and current_udp >
            baseline_data["udp_per_sec"] * 3
        )

        icmp_anomaly = (
            baseline_data["icmp_per_sec"] > 0
            and current_icmp >
            baseline_data["icmp_per_sec"] * 3
        )

        port_anomaly = (
            baseline_data["unique_ports"] > 0
            and current_ports >
            baseline_data["unique_ports"] * 3
        )

        # Count abnormal metrics
        anomaly_count = sum([
            packet_anomaly,
            byte_anomaly,
            tcp_anomaly,
            udp_anomaly,
            icmp_anomaly,
            port_anomaly
        ])

        # Alert only when at least 2 metrics are abnormal
        if anomaly_count >= 2:

            current_alerts.add(("BASELINE_ANOMALY", ip))

            baseline_alert=BaselineAlert.objects.create(
                session=nids_session,
                source_ip=ip,
                severity="MEDIUM",
                reason="Current incoming traffic significantly exceeds the learned baseline",
                abnormal_metrics=anomaly_count,

                current_packets_per_sec=current_packets,
                baseline_packets_per_sec=baseline_data["packets_per_sec"],

                current_bytes_per_sec=current_bytes,
                baseline_bytes_per_sec=baseline_data["bytes_per_sec"],

                current_tcp_per_sec=current_tcp,
                baseline_tcp_per_sec=baseline_data["tcp_per_sec"],

                current_udp_per_sec=current_udp,
                baseline_udp_per_sec=baseline_data["udp_per_sec"],

                current_icmp_per_sec=current_icmp,
                baseline_icmp_per_sec=baseline_data["icmp_per_sec"],

                current_unique_ports=current_ports,
                baseline_unique_ports=baseline_data["unique_ports"]
            )

            channel_layer = get_channel_layer()

            async_to_sync(
                    channel_layer.group_send
                )(
                    "nids_live",
                    {
                        "type": "nids_message",
                        "data": {
                            "type": "baseline_alert",
                            "alert": {
                                "source_ip": baseline_alert.source_ip,
                                "severity": baseline_alert.severity,
                                "reason": baseline_alert.reason,
                                "abnormal_metrics": baseline_alert.abnormal_metrics,
                                "current_packets_per_sec": baseline_alert.current_packets_per_sec,
                                "baseline_packets_per_sec": baseline_alert.baseline_packets_per_sec,
                                "current_bytes_per_sec": baseline_alert.current_bytes_per_sec,
                                "baseline_bytes_per_sec": baseline_alert.baseline_bytes_per_sec,
                                "current_tcp_per_sec": baseline_alert.current_tcp_per_sec,
                                "baseline_tcp_per_sec": baseline_alert.baseline_tcp_per_sec,
                                "current_udp_per_sec": baseline_alert.current_udp_per_sec,
                                "baseline_udp_per_sec": baseline_alert.baseline_udp_per_sec,
                                "current_icmp_per_sec": baseline_alert.current_icmp_per_sec,
                                "baseline_icmp_per_sec": baseline_alert.baseline_icmp_per_sec,
                                "current_unique_ports": baseline_alert.current_unique_ports,
                                "baseline_unique_ports": baseline_alert.baseline_unique_ports,
                            }
                        }
                    }
                )

            add_alert(
                "BASELINE_ANOMALY",
                ip,
                "MEDIUM",
                "Current incoming traffic significantly exceeds the learned baseline",
                anomaly_count,
                2
            )

            print("Source IP            :", ip)
            print("Abnormal Metrics     :", anomaly_count)

            print("Current Packets/sec  :", round(current_packets, 2))
            print(
                "Baseline Packets/sec :",
                round(baseline_data["packets_per_sec"], 2)
            )

            print("Current Bytes/sec    :", round(current_bytes, 2))
            print(
                "Baseline Bytes/sec  :",
                round(baseline_data["bytes_per_sec"], 2)
            )

            print("Current TCP/sec      :", round(current_tcp, 2))
            print(
                "Baseline TCP/sec    :",
                round(baseline_data["tcp_per_sec"], 2)
            )

            print("Current UDP/sec      :", round(current_udp, 2))
            print(
                "Baseline UDP/sec    :",
                round(baseline_data["udp_per_sec"], 2)
            )

            print("Current ICMP/sec     :", round(current_icmp, 2))
            print(
                "Baseline ICMP/sec   :",
                round(baseline_data["icmp_per_sec"], 2)
            )

            print("Current Unique Ports :", current_ports)
            print(
                "Baseline Ports       :",
                round(baseline_data["unique_ports"], 2)
            )

            print("-----------------------------------------------")

    # Remove alerts that are no longer active
    for alert_key in list(active_alerts):

        if (
            alert_key[0] == "BASELINE_ANOMALY"
            and alert_key not in current_alerts
        ):
            del active_alerts[alert_key]

    print("===============================================\n")

#displaying the packets 
def show_rolling_traffic(seconds):

    stats = analyze_recent_traffic(seconds)

    print(f"\n========== LAST {seconds} SECOND TRAFFIC ==========\n")

    for ip, data in stats.items():

        packets_per_sec = data["packet_count"] / seconds
        bytes_per_sec = data["total_bytes"] / seconds

        print("IP                    :", ip)
        print("Packets               :", data["packet_count"])
        print("Packets/sec           :", packets_per_sec)
        print("Bytes/sec             :", bytes_per_sec)
        print("Destination Ports     :", data["destination_ports"])
        print("Connection Port Count :",data["connection_port_counts"])
        print("source MAC            :",data["source_macs"])
        print("Incoming Ports        :", data["incoming_ports"])
        print("Destination IPs       :", data["destination_ips"])
        print("TCP Packets           :", data["tcp_count"])
        print("SYN Packets           :", data["syn_count"])
        print("UDP Packets           :", data["udp_count"])
        print("ICMP Packets          :", data["icmp_count"])
        print("--------------------------------------")

    print("============================================\n")

#creating actual alert system to see which alert type is it when how why 
def add_alert(alert_type, source_ip, severity, reason, observed, threshold):

    alert_key = (alert_type, source_ip)

    # Dont create duplicate alert if this alert is already active
    if alert_key in active_alerts:
        return

    alert = {
        "type": alert_type,
        "source_ip": source_ip,
        "severity": severity,
        "reason": reason,
        "observed": observed,
        "threshold": threshold,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    active_alerts[alert_key] = True
    alerts.append(alert)

    #saving fixed rules in fixed rules db table
    fixed_rules_alert={
        "PORT_SCAN",
        "TRAFFIC_FLOOD",
        "SYN_FLOOD",
        "UDP_FLOOD",
        "ICMP_FLOOD",
        "CONNECTION_BURST"
    }

    if alert_type in fixed_rules_alert:
        FixedRuleAlert.objects.create(
            session=nids_session,
            alert_type=alert_type,
            source_ip=source_ip,
            severity=severity,
            reason=reason,
            observed=observed,
            threshold=threshold
        )

    print("\n SECURITY ALERT")
    print("Type       :", alert["type"])
    print("Source IP  :", alert["source_ip"])
    print("Severity   :", alert["severity"])
    print("Reason     :", alert["reason"])
    print("Observed   :", alert["observed"])
    print("Threshold  :", alert["threshold"])
    print("Time       :", alert["timestamp"])

    channel_layer = get_channel_layer()

    async_to_sync(
        channel_layer.group_send
    )(
        "nids_live",
        {
            "type": "nids_message",
            "data": {
                "type": "fixed_rule_alert",
                "alert": alert
            }
        }
    )

#port scan detection function
def detect_port_scan_rolling():

    print("\n========== PORT ANALYSIS ==========\n")

    stats = analyze_recent_traffic(10)

    current_alerts = set()

    for ip, data in stats.items():

        unique_incoming_ports = len(data["incoming_ports"])

        if unique_incoming_ports > 10:

            current_alerts.add(("PORT_SCAN", ip))

            add_alert(
                "PORT_SCAN",
                ip,
                "HIGH",
                "Multiple unique incoming ports detected within a rolling 10-second window",
                unique_incoming_ports,
                10
            )

    for alert_key in list(active_alerts):

        if alert_key[0] == "PORT_SCAN" and alert_key not in current_alerts:
            del active_alerts[alert_key]

#flood attack detection 
def detect_flood():

    stats = analyze_recent_traffic(10)
    current_alerts = set()

    for ip, data in stats.items():

        incoming_packets = data["incoming_packet_count"]
        packets_per_sec = incoming_packets / 10

        if packets_per_sec > 100 and incoming_packets > 1000:

            current_alerts.add(("TRAFFIC_FLOOD", ip))

            add_alert(
                "TRAFFIC_FLOOD",
                ip,
                "HIGH",
                "Abnormally high incoming packet rate detected within a rolling 10-second window",
                packets_per_sec,
                100
            )

    for alert_key in list(active_alerts):

        if (
            alert_key[0] == "TRAFFIC_FLOOD"
            and alert_key not in current_alerts
        ):
            del active_alerts[alert_key]

# UDP flood detection
def detect_udp_flood():

    print("\n========== UDP FLOOD ANALYSIS ==========\n")

    stats = analyze_recent_traffic(10)

    current_alerts = set()

    for ip, data in stats.items():

        udp_packets = data["udp_count"]
        udp_per_sec = udp_packets / 10

        if udp_per_sec > 100 and udp_packets > 1000:

            current_alerts.add(("UDP_FLOOD", ip))

            add_alert(
                "UDP_FLOOD",
                ip,
                "HIGH",
                "Abnormally high UDP packet rate detected within a rolling 10-second window",
                udp_per_sec,
                100
            )

            print("UDP Packets        :", udp_packets)
            print("UDP/sec             :", udp_per_sec)

    # Remove alerts that are no longer active
    for alert_key in list(active_alerts):

        if alert_key[0] == "UDP_FLOOD" and alert_key not in current_alerts:
            del active_alerts[alert_key]

    print("========================================\n")  

# ICMP flood detection
def detect_icmp_flood():

    print("\n========== ICMP FLOOD ANALYSIS ==========\n")

    stats = analyze_recent_traffic(10)

    current_alerts = set()

    for ip, data in stats.items():

        icmp_packets = data["icmp_count"]
        icmp_per_sec = icmp_packets / 10

        if icmp_per_sec > 100 and icmp_packets > 1000:

            current_alerts.add(("ICMP_FLOOD", ip))

            add_alert(
                "ICMP_FLOOD",
                ip,
                "HIGH",
                "Abnormally high ICMP packet rate detected within a rolling 10-second window",
                icmp_per_sec,
                100
            )

            print("ICMP Packets       :", icmp_packets)
            print("ICMP/sec            :", icmp_per_sec)

    # Remove alerts that are no longer active
    for alert_key in list(active_alerts):

        if alert_key[0] == "ICMP_FLOOD" and alert_key not in current_alerts:
            del active_alerts[alert_key]

    print("========================================\n")

# TCP connection burst detection
def detect_connection_burst():

    print("\n========== CONNECTION BURST ANALYSIS ==========\n")

    stats = analyze_recent_traffic(10)

    current_alerts = set()

    for ip, data in stats.items():

        for port, attempts in data["connection_port_counts"].items():

            if attempts > 20:

                current_alerts.add(("CONNECTION_BURST", ip))

                add_alert(
                    "CONNECTION_BURST",
                    ip,
                    "HIGH",
                    "High number of incoming TCP connection attempts to the same service within a rolling 10-second window",
                    attempts,
                    20
                )

                print("Source IP          :", ip)
                print("Destination Port   :", port)
                print("Connection Attempts:", attempts)

    # Remove alerts that are no longer active
    for alert_key in list(active_alerts):

        if alert_key[0] == "CONNECTION_BURST" and alert_key not in current_alerts:
            del active_alerts[alert_key]

    print("==============================================\n")

#TCP-SYN flood detection engine 
def detect_syn_flood():

    print("\n========== SYN FLOOD ANALYSIS ==========\n")

    current_time = time.time()
    current_alerts = set()

    # Analyze TCP flows from the last 10 seconds
    source_stats = defaultdict(lambda: {
        "syn_attempts": 0,
        "incomplete": 0,
        "completed": 0
    })

    for flow, data in tcp_flows.items():

        if current_time - data["timestamp"] <= 10:

            source_ip = flow[0]

            source_stats[source_ip]["syn_attempts"] += 1

            # Handshake completed
            if data["syn_ack"] and data["ack"]:
                source_stats[source_ip]["completed"] += 1

            else:
                source_stats[source_ip]["incomplete"] += 1

    for ip, data in source_stats.items():

        syn_attempts = data["syn_attempts"]
        incomplete = data["incomplete"]

        if syn_attempts == 0:
            continue

        syn_per_sec = syn_attempts / 10

        incomplete_ratio = incomplete / syn_attempts

        # SYN flood condition
        if syn_per_sec > 50 and incomplete_ratio > 0.8:

            current_alerts.add(("SYN_FLOOD", ip))

            add_alert(
                "SYN_FLOOD",
                ip,
                "HIGH",
                "High SYN rate with a high percentage of incomplete TCP handshakes",
                round(incomplete_ratio * 100, 2),
                80
            )

            print("SYN Attempts       :", syn_attempts)
            print("Incomplete         :", incomplete)
            print("Completed          :", data["completed"])
            print("SYN/sec            :", syn_per_sec)
            print("Incomplete Ratio   :", round(incomplete_ratio * 100, 2), "%")

    # Remove alerts that are no longer active
    for alert_key in list(active_alerts):

        if alert_key[0] == "SYN_FLOOD" and alert_key not in current_alerts:
            del active_alerts[alert_key]

    print("========================================\n")

def send_traffic_update():

    stats = analyze_recent_traffic(10)

    channel_layer = get_channel_layer()

    traffic_data = []

    for ip, data in stats.items():

        packets_per_sec = data["packet_count"] / 10

        traffic_data.append({
            "source_ip": ip,
            "packets": data["packet_count"],
            "packets_per_sec": packets_per_sec,
            "bytes": data["total_bytes"],
            "tcp": data["tcp_count"],
            "udp": data["udp_count"],
            "icmp": data["icmp_count"],
            "syn": data["syn_count"],
            "incoming_packets": data["incoming_packet_count"]
        })

    async_to_sync(
        channel_layer.group_send
    )(
        "nids_live",
        {
            "type": "nids_message",
            "data": {
                "type": "traffic",
                "traffic": traffic_data
            }
        }
    )

#sending updated stats torough sockets
def send_statistics_update():

    if nids_session is None:
        return

    channel_layer = get_channel_layer()

    async_to_sync(
        channel_layer.group_send
    )(
        "nids_live",
        {
            "type": "nids_message",
            "data": {
                "type": "statistics",

                "total_packets": nids_session.total_packets,
                "total_bytes": nids_session.total_bytes,

                "unique_source_ips": nids_session.unique_source_ips,
                "unique_destination_ips": nids_session.unique_destination_ips,
                "active_sources": nids_session.active_sources,

                "total_tcp": nids_session.total_tcp,
                "total_syn": nids_session.total_syn,
                "total_udp": nids_session.total_udp,
                "total_icmp": nids_session.total_icmp,
                "total_other": nids_session.total_other,

                "total_incoming": nids_session.total_incoming,
                "total_outgoing": nids_session.total_outgoing,
                "total_local": nids_session.total_local,
                "total_other_direction": nids_session.total_other_direction
            }
        }
    )
    
def start_capture():

    global nids_session

    # Recover any previous session that was not closed properly

    open_sessions = NIDSSession.objects.filter(
        stopped_at__isnull=True
    )

    for old_session in open_sessions:

        old_session.stopped_at = timezone.now()
        old_session.save()

        print("\nRecovered previous NIDS session")
        print("Session ID:", old_session.id)

    # Create a new session

    nids_session = NIDSSession.objects.create()
    # Reset session statistics for the new NIDS session
    session_stats["total_packets"] = 0
    session_stats["total_bytes"] = 0
    session_stats["unique_source_ips"].clear()
    session_stats["unique_destination_ips"].clear()
    session_stats["total_tcp"] = 0
    session_stats["total_syn"] = 0
    session_stats["total_udp"] = 0
    session_stats["total_icmp"] = 0
    session_stats["total_other"] = 0
    session_stats["total_incoming"] = 0
    session_stats["total_outgoing"] = 0
    session_stats["total_local"] = 0
    session_stats["total_other_direction"] = 0

    source_last_seen.clear()

    print("\nNIDS Session Started")
    print("Session ID:", nids_session.id)

    last_report=time.time()
    try:
        while True:
            sniff(
                prn=packet_received,
                timeout=1,
                store=False
            )
            if time.time() - last_report >= 10:
                show_rolling_traffic(10)

                send_traffic_update()

                if nids_session is not None:

                    current_time = time.time()

                    active_source_count = sum(
                        1
                        for last_seen in source_last_seen.values()
                        if current_time - last_seen <= 30
                    )

                    nids_session.total_packets = session_stats["total_packets"]
                    nids_session.total_bytes = session_stats["total_bytes"]

                    nids_session.unique_source_ips = len(
                        session_stats["unique_source_ips"]
                    )

                    nids_session.unique_destination_ips = len(
                        session_stats["unique_destination_ips"]
                    )

                    nids_session.active_sources = active_source_count

                    nids_session.total_tcp = session_stats["total_tcp"]
                    nids_session.total_syn = session_stats["total_syn"]
                    nids_session.total_udp = session_stats["total_udp"]
                    nids_session.total_icmp = session_stats["total_icmp"]
                    nids_session.total_other = session_stats["total_other"]

                    nids_session.total_incoming = session_stats["total_incoming"]
                    nids_session.total_outgoing = session_stats["total_outgoing"]
                    nids_session.total_local = session_stats["total_local"]
                    nids_session.total_other_direction = session_stats["total_other_direction"]

                    nids_session.save()
    
                send_statistics_update()
                collect_baseline_sample()
                if baseline_ready:
                    show_baseline()
                detect_port_scan_rolling()
                detect_flood()
                detect_syn_flood()
                detect_udp_flood()
                detect_icmp_flood()
                detect_connection_burst()
                detect_baseline_anomaly()
                last_report=time.time()
    except KeyboardInterrupt:
        print("\n NIDS Stopped")


if __name__ == "__main__":
    print("Starting packet capture...")
    print("Press CTRL+C to stop.")

    start_capture()

