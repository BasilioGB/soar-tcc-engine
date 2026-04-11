from django.urls import re_path

from . import consumers

websocket_urlpatterns = [
    re_path(r"^ws/incidents/(?P<incident_id>\d+)/$", consumers.IncidentConsumer.as_asgi(), name="ws_incident"),
    re_path(r"^ws/notify/$", consumers.NotifyConsumer.as_asgi(), name="ws_notify"),
]
