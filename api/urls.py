from django.urls import include, path
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from .views import (
    ArtifactViewSet,
    ExecutionViewSet,
    IncidentStreamView,
    IncidentViewSet,
    IncidentMetricsView,
    LabelSuggestView,
    MeView,
    PlaybookViewSet,
    UserSearchView,
)

router = DefaultRouter()
router.register(r"incidents", IncidentViewSet, basename="incidents")
router.register(r"artifacts", ArtifactViewSet, basename="artifacts")
router.register(r"playbooks", PlaybookViewSet, basename="playbooks")
router.register(r"executions", ExecutionViewSet, basename="executions")

urlpatterns = [
    path("auth/token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("auth/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("me/", MeView.as_view(), name="me"),
    path("users/search/", UserSearchView.as_view(), name="user-search"),
    path("labels/suggest/", LabelSuggestView.as_view(), name="label-suggest"),
    path("incidents/<int:pk>/stream/", IncidentStreamView.as_view(), name="incident-stream"),
    path("metrics/incidents/", IncidentMetricsView.as_view(), name="incident-metrics"),
    path("", include(router.urls)),
]
