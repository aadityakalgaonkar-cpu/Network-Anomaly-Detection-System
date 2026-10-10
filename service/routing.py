from django.urls import path
from .consumer import NIDSConsumer


websocket_urlpatterns = [
    path("ws/nids/", NIDSConsumer.as_asgi()),
]