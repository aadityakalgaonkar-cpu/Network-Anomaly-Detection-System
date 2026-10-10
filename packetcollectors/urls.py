from django.contrib import admin
from django.urls import path

from packetcollectors import views


urlpatterns = [
path("admin/", admin.site.urls),
path("", views.admin_login, name="root"),
path("login/", views.admin_login, name="login"),
path("logout/", views.admin_logout, name="logout"),
path("dashboard/", views.dashboard, name="dashboard"),
path("live-traffic/", views.live_traffic, name="live_traffic"),
path("fixed-alerts/", views.fixed_alerts, name="fixed_alerts"),
path("baselines/", views.baselines, name="baselines"),
path("baseline-alerts/", views.baseline_alerts, name="baseline_alerts"),
path("statistics/", views.statistics, name="statistics"),
path("history/", views.history, name="history"),
path("history/fixed-rules/", views.fixed_rules_history, name="fixed_rules_history"),
path("history/packets/", views.packet_history, name="packet_history"),
path("history/baseline-alerts/", views.baseline_alert_history, name="baseline_alert_history"),
path("history/fixed-rules/report/", views.fixed_rules_report, name="fixed_rules_report"),
path("history/packets/report/", views.packet_report, name="packet_report"),
path("history/baseline-alerts/report/", views.baseline_alert_report, name="baseline_alert_report"),
path("aboutus/",views.aboutus,name="aboutus"),
path("dashboard/alerts/poll/", views.dashboard_alert_poll, name="dashboard_alert_poll"),
]