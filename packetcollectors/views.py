from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required

from service.network_utils import get_local_ips

from service.models import (
    FixedRuleAlert,
    Baseline,
    BaselineAlert,
    NIDSSession,
    AllPacket,
)

import csv


# ============================================================
# ALLOWED ADMIN USERS
# ============================================================

ALLOWED_ADMINS = [
    "aaditya",
    "pranav",
]


# ============================================================
# LOGIN
# ============================================================

def admin_login(request):

    # Already logged in
    if request.user.is_authenticated:
        return redirect("dashboard")

    error = None

    if request.method == "POST":

        username = request.POST.get("username")
        password = request.POST.get("password")

        # First check username whitelist
        if username not in ALLOWED_ADMINS:

            error = "Access denied."

        else:

            # Check Django username + password
            user = authenticate(
                request,
                username=username,
                password=password
            )

            if user is not None:

                login(request, user)

                return redirect("dashboard")

            else:

                error = "Invalid username or password."

    return render(
        request,
        "login.html",
        {
            "error": error
        }
    )


# ============================================================
# LOGOUT
# ============================================================

def admin_logout(request):

    if request.method == "POST":

        logout(request)

    return redirect("login")


# ============================================================
# DASHBOARD
# ============================================================

@login_required
def dashboard(request):

    local_ips = get_local_ips()

    latest_fixed_alert = (
        FixedRuleAlert.objects.order_by("-id")
        .values_list("id", flat=True)
        .first()
    )

    latest_baseline_alert = (
        BaselineAlert.objects.order_by("-id")
        .values_list("id", flat=True)
        .first()
    )

    return render(
        request,
        "dashboard.html",
        {
            "local_ips": sorted(local_ips),
            "latest_fixed_alert_id": latest_fixed_alert or 0,
            "latest_baseline_alert_id": latest_baseline_alert or 0,
        }
    )

@login_required
def dashboard_alert_poll(request):

    try:
        last_fixed_id = max(
            0, int(request.GET.get("fixed_id", 0))
        )

        last_baseline_id = max(
            0, int(request.GET.get("baseline_id", 0))
        )

    except (ValueError, TypeError):
        return JsonResponse(
            {"error": "Invalid alert ID"},
            status=400
        )

    fixed_alerts = FixedRuleAlert.objects.filter(
        id__gt=last_fixed_id
    ).order_by("id")[:10]

    baseline_alerts = BaselineAlert.objects.filter(
        id__gt=last_baseline_id
    ).order_by("id")[:10]

    alerts = []

    for alert in fixed_alerts:
        alerts.append({
            "id": alert.id,
            "category": "FIXED RULE ALERT",
            "alert_type": alert.alert_type,
            "source_ip": str(alert.source_ip),
            "severity": alert.severity,
            "reason": alert.reason,
            "timestamp": alert.timestamp.isoformat(),
        })

    for alert in baseline_alerts:
        alerts.append({
            "id": alert.id,
            "category": "BASELINE ALERT",
            "alert_type": "BASELINE_ANOMALY",
            "source_ip": str(alert.source_ip),
            "severity": alert.severity,
            "reason": alert.reason,
            "timestamp": alert.timestamp.isoformat(),
        })

    alerts.sort(key=lambda alert: alert["timestamp"])

    return JsonResponse({
        "alerts": alerts,
        "latest_fixed_id": max(
            [last_fixed_id] + [
                alert.id for alert in fixed_alerts
            ]
        ),
        "latest_baseline_id": max(
            [last_baseline_id] + [
                alert.id for alert in baseline_alerts
            ]
        ),
    })

# ============================================================
# LIVE TRAFFIC
# ============================================================

@login_required
def live_traffic(request):

    return render(
        request,
        "live_traffic.html"
    )


# ============================================================
# FIXED RULE ALERTS
# ============================================================

@login_required
def fixed_alerts(request):

    current_session = NIDSSession.objects.filter(
        stopped_at__isnull=True
    ).order_by("-started_at").first()

    if current_session:

        alerts = FixedRuleAlert.objects.filter(
            session=current_session
        ).order_by("-timestamp", "-id")

    else:

        alerts = FixedRuleAlert.objects.none()

    return render(
        request,
        "fixed_alerts.html",
        {
            "alerts": alerts
        }
    )


# ============================================================
# BASELINES
# ============================================================

@login_required
def baselines(request):

    current_session = NIDSSession.objects.filter(
        stopped_at__isnull=True
    ).order_by("-started_at").first()

    if current_session:

        baselines = Baseline.objects.filter(
            session=current_session
        ).order_by("-updated_at", "-id")

    else:

        baselines = Baseline.objects.none()

    return render(
        request,
        "baselines.html",
        {
            "baselines": baselines
        }
    )


# ============================================================
# BASELINE ALERTS
# ============================================================

@login_required
def baseline_alerts(request):

    current_session = NIDSSession.objects.filter(
        stopped_at__isnull=True
    ).order_by("-started_at").first()

    if current_session:

        alerts = BaselineAlert.objects.filter(
            session=current_session
        ).order_by("-timestamp", "-id")

    else:

        alerts = BaselineAlert.objects.none()

    return render(
        request,
        "baseline_alerts.html",
        {
            "alerts": alerts
        }
    )


# ============================================================
# STATISTICS
# ============================================================

@login_required
def statistics(request):

    current_session = NIDSSession.objects.filter(
        stopped_at__isnull=True
    ).order_by("-started_at").first()

    return render(
        request,
        "statistics.html",
        {
            "session": current_session
        }
    )


# ============================================================
# HISTORY MAIN PAGE
# ============================================================

@login_required
def history(request):

    return render(
        request,
        "history.html"
    )


# ============================================================
# FIXED RULES HISTORY
# ============================================================

@login_required
def fixed_rules_history(request):

    # ALL sessions
    alerts = FixedRuleAlert.objects.all().order_by(
        "-timestamp",
        "-id"
    )

    return render(
        request,
        "fixed_rules_history.html",
        {
            "alerts": alerts
        }
    )


# ============================================================
# PACKET HISTORY
# ============================================================

@login_required
def packet_history(request):

    # ALL packets from ALL sessions
    packets = AllPacket.objects.all().order_by(
        "-timestamp",
        "-id"
    )

    return render(
        request,
        "packet_history.html",
        {
            "packets": packets
        }
    )


# ============================================================
# BASELINE ALERT HISTORY
# ============================================================

@login_required
def baseline_alert_history(request):

    # ALL baseline alerts from ALL sessions
    alerts = BaselineAlert.objects.all().order_by(
        "-timestamp",
        "-id"
    )

    return render(
        request,
        "baseline_alert_history.html",
        {
            "alerts": alerts
        }
    )


# ============================================================
# FIXED RULES CSV REPORT
# ============================================================

@login_required
def fixed_rules_report(request):

    alerts = FixedRuleAlert.objects.all()

    # Filters
    alert_type = request.GET.get("alert_type")
    severity = request.GET.get("severity")
    source_ip = request.GET.get("source_ip")
    status = request.GET.get("status")

    if alert_type:

        alerts = alerts.filter(
            alert_type=alert_type
        )

    if severity:

        alerts = alerts.filter(
            severity=severity
        )

    if source_ip:

        alerts = alerts.filter(
            source_ip=source_ip
        )

    if status:

        alerts = alerts.filter(
            status=status
        )

    # Latest first
    alerts = alerts.order_by(
        "-timestamp",
        "-id"
    )

    response = HttpResponse(
        content_type="text/csv"
    )

    response["Content-Disposition"] = (
        'attachment; filename="fixed_rules_report.csv"'
    )

    writer = csv.writer(response)

    # CSV header
    writer.writerow([
        "Session ID",
        "Alert Type",
        "Source IP",
        "Severity",
        "Reason",
        "Observed",
        "Threshold",
        "Status",
        "Timestamp",
    ])

    # CSV data
    for alert in alerts:

        writer.writerow([
            alert.session_id,
            alert.alert_type,
            alert.source_ip,
            alert.severity,
            alert.reason,
            alert.observed,
            alert.threshold,
            alert.status,
            alert.timestamp,
        ])

    return response


# ============================================================
# PACKET CSV REPORT
# ============================================================

@login_required
def packet_report(request):

    packets = AllPacket.objects.all()

    # Filters
    protocol = request.GET.get("protocol")
    direction = request.GET.get("direction")
    source_ip = request.GET.get("source_ip")
    destination_ip = request.GET.get("destination_ip")

    if protocol:

        packets = packets.filter(
            protocol=protocol
        )

    if direction:

        packets = packets.filter(
            direction=direction
        )

    if source_ip:

        packets = packets.filter(
            source_ip=source_ip
        )

    if destination_ip:

        packets = packets.filter(
            destination_ip=destination_ip
        )

    # IMPORTANT:
    # Do NOT order globally by packet_number because
    # packet numbers can restart in every session.
    packets = packets.order_by(
        "-timestamp",
        "-id"
    )

    response = HttpResponse(
        content_type="text/csv"
    )

    response["Content-Disposition"] = (
        'attachment; filename="packet_history_report.csv"'
    )

    writer = csv.writer(response)

    # CSV header
    writer.writerow([
        "Session ID",
        "Packet Number",
        "Timestamp",
        "Source IP",
        "Destination IP",
        "Source MAC",
        "Destination MAC",
        "Protocol",
        "Source Port",
        "Destination Port",
        "Packet Size",
        "Direction",
        "TCP Flags",
        "TCP",
        "UDP",
        "ICMP",
        "SYN",
    ])

    # CSV data
    for packet in packets:

        writer.writerow([
            packet.session_id,
            packet.packet_number,
            packet.timestamp,
            packet.source_ip,
            packet.destination_ip,
            packet.source_mac,
            packet.destination_mac,
            packet.protocol,
            packet.source_port,
            packet.destination_port,
            packet.packet_size,
            packet.direction,
            packet.tcp_flags,
            packet.is_tcp,
            packet.is_udp,
            packet.is_icmp,
            packet.is_syn,
        ])

    return response


# ============================================================
# BASELINE ALERT CSV REPORT
# ============================================================

@login_required
def baseline_alert_report(request):

    alerts = BaselineAlert.objects.all()

    # Filters
    severity = request.GET.get("severity")
    source_ip = request.GET.get("source_ip")
    status = request.GET.get("status")

    if severity:

        alerts = alerts.filter(
            severity=severity
        )

    if source_ip:

        alerts = alerts.filter(
            source_ip=source_ip
        )

    if status:

        alerts = alerts.filter(
            status=status
        )

    alerts = alerts.order_by(
        "-timestamp",
        "-id"
    )

    response = HttpResponse(
        content_type="text/csv"
    )

    response["Content-Disposition"] = (
        'attachment; filename="baseline_alert_report.csv"'
    )

    writer = csv.writer(response)

    # CSV header
    writer.writerow([
        "Session ID",
        "Source IP",
        "Severity",
        "Reason",
        "Abnormal Metrics",

        "Current Packets/sec",
        "Baseline Packets/sec",

        "Current Bytes/sec",
        "Baseline Bytes/sec",

        "Current TCP/sec",
        "Baseline TCP/sec",

        "Current UDP/sec",
        "Baseline UDP/sec",

        "Current ICMP/sec",
        "Baseline ICMP/sec",

        "Current Unique Ports",
        "Baseline Unique Ports",

        "Status",
        "Timestamp",
    ])

    # CSV data
    for alert in alerts:

        writer.writerow([
            alert.session_id,
            alert.source_ip,
            alert.severity,
            alert.reason,
            alert.abnormal_metrics,

            alert.current_packets_per_sec,
            alert.baseline_packets_per_sec,

            alert.current_bytes_per_sec,
            alert.baseline_bytes_per_sec,

            alert.current_tcp_per_sec,
            alert.baseline_tcp_per_sec,

            alert.current_udp_per_sec,
            alert.baseline_udp_per_sec,

            alert.current_icmp_per_sec,
            alert.baseline_icmp_per_sec,

            alert.current_unique_ports,
            alert.baseline_unique_ports,

            alert.status,
            alert.timestamp,
        ])

    return response

def aboutus(request):
    return render(request,"aboutus.html")