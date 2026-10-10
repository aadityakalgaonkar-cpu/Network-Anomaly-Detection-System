from django.db import models

#calculate the culumative total and store it since we start and stop the nids 
class NIDSSession(models.Model):
    started_at = models.DateTimeField(auto_now_add=True)
    stopped_at = models.DateTimeField(null=True, blank=True)

    total_packets = models.BigIntegerField(default=0)
    total_bytes = models.BigIntegerField(default=0)

    unique_source_ips = models.IntegerField(default=0)
    unique_destination_ips = models.IntegerField(default=0)

    active_sources = models.IntegerField(default=0)

    total_tcp = models.BigIntegerField(default=0)
    total_syn = models.BigIntegerField(default=0)
    total_udp = models.BigIntegerField(default=0)
    total_icmp = models.BigIntegerField(default=0)
    total_other = models.BigIntegerField(default=0)

    total_incoming = models.BigIntegerField(default=0)
    total_outgoing = models.BigIntegerField(default=0)
    total_local = models.BigIntegerField(default=0)
    total_other_direction = models.BigIntegerField(default=0)

    def __str__(self):
        return f"NIDS Session {self.id}"

#store the every baseline created 
class Baseline(models.Model):

    session = models.ForeignKey(
            NIDSSession,
            on_delete=models.CASCADE,
            related_name="baselines",
            null=True,
            blank=True
        )
    source_ip = models.GenericIPAddressField()
    packets_per_sec = models.FloatField(default=0)
    bytes_per_sec = models.FloatField(default=0)
    tcp_per_sec = models.FloatField(default=0)
    udp_per_sec = models.FloatField(default=0)
    icmp_per_sec = models.FloatField(default=0)

    unique_ports = models.FloatField(default=0)
    unique_destination_ips = models.FloatField(default=0)

    sample_count = models.IntegerField(default=0)

    status = models.CharField(max_length=20, default="LEARNING")
    activity = models.CharField(max_length=20, default="INACTIVE")

    first_seen = models.DateTimeField(null=True, blank=True)
    last_seen = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.source_ip

#store every alert as per baseline
class BaselineAlert(models.Model):

    session = models.ForeignKey(
        NIDSSession,
        on_delete=models.CASCADE,
        related_name="baseline_alerts",
        null=True,
        blank=True
    )
    source_ip = models.GenericIPAddressField()
    severity = models.CharField(max_length=20, default="MEDIUM")
    reason = models.TextField()

    abnormal_metrics = models.IntegerField()

    current_packets_per_sec = models.FloatField(default=0)
    baseline_packets_per_sec = models.FloatField(default=0)

    current_bytes_per_sec = models.FloatField(default=0)
    baseline_bytes_per_sec = models.FloatField(default=0)

    current_tcp_per_sec = models.FloatField(default=0)
    baseline_tcp_per_sec = models.FloatField(default=0)

    current_udp_per_sec = models.FloatField(default=0)
    baseline_udp_per_sec = models.FloatField(default=0)

    current_icmp_per_sec = models.FloatField(default=0)
    baseline_icmp_per_sec = models.FloatField(default=0)

    current_unique_ports = models.FloatField(default=0)
    baseline_unique_ports = models.FloatField(default=0)

    timestamp = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, default="ACTIVE")

    def __str__(self):
        return f"BASELINE_ANOMALY - {self.source_ip}"


#store the alerts as per fixed rules engine 
class FixedRuleAlert(models.Model):

    session = models.ForeignKey(
        NIDSSession,
        on_delete=models.CASCADE,
        related_name="fixed_alerts",
        null=True,
        blank=True
    )

    alert_type = models.CharField(max_length=50)
    source_ip = models.GenericIPAddressField()
    severity = models.CharField(max_length=20)
    reason = models.TextField()
    observed = models.FloatField()
    threshold = models.FloatField()
    timestamp = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, default="ACTIVE")

    def __str__(self):
        return f"{self.alert_type} - {self.source_ip}"

#storing all packets in db
class AllPacket(models.Model):

    session = models.ForeignKey(
        NIDSSession,
        on_delete=models.CASCADE,
        related_name="packets"
    )

    packet_number = models.BigIntegerField()

    timestamp = models.DateTimeField()

    source_ip = models.GenericIPAddressField(
        null=True,
        blank=True
    )

    destination_ip = models.GenericIPAddressField(
        null=True,
        blank=True
    )

    source_mac = models.CharField(
        max_length=50,
        null=True,
        blank=True
    )

    destination_mac = models.CharField(
        max_length=50,
        null=True,
        blank=True
    )

    protocol = models.CharField(
        max_length=20
    )

    source_port = models.IntegerField(
        null=True,
        blank=True
    )

    destination_port = models.IntegerField(
        null=True,
        blank=True
    )

    packet_size = models.BigIntegerField()

    direction = models.CharField(
        max_length=20
    )

    tcp_flags = models.CharField(
        max_length=20,
        null=True,
        blank=True
    )

    is_tcp = models.BooleanField(default=False)

    is_udp = models.BooleanField(default=False)

    is_icmp = models.BooleanField(default=False)

    is_syn = models.BooleanField(default=False)

    def __str__(self):
        return f"Packet {self.packet_number} - {self.source_ip}"