from __future__ import annotations

from datetime import timedelta

from django.db.models import Avg, Count, DurationField, ExpressionWrapper, F, QuerySet
from django.db.models.functions import Coalesce
from django.utils import timezone

from .models import Incident


def _duration_avg(queryset: QuerySet, duration_expression: ExpressionWrapper) -> dict[str, object]:
    annotated = queryset.annotate(metric_delta=duration_expression)
    aggregate = annotated.aggregate(avg=Avg("metric_delta"), count=Count("id"))
    return {"avg": aggregate["avg"], "count": aggregate["count"] or 0}


def calculate_mttd_mttr(*, queryset: QuerySet | None = None, window: timedelta | None = None) -> dict[str, dict]:
    qs = queryset or Incident.objects.all()
    if window:
        cutoff = timezone.now() - window
        qs = qs.filter(detected_at__gte=cutoff)

    detection_qs = qs.filter(occurred_at__isnull=False, detected_at__isnull=False)
    detection = _duration_avg(
        detection_qs,
        ExpressionWrapper(F("detected_at") - F("occurred_at"), output_field=DurationField()),
    )

    resolution_qs = qs.filter(detected_at__isnull=False).annotate(
        lifecycle_resolution=Coalesce("resolved_at", "closed_at")
    ).filter(lifecycle_resolution__isnull=False)
    resolution = _duration_avg(
        resolution_qs,
        ExpressionWrapper(F("lifecycle_resolution") - F("detected_at"), output_field=DurationField()),
    )

    response_qs = qs.filter(detected_at__isnull=False, responded_at__isnull=False)
    response = _duration_avg(
        response_qs,
        ExpressionWrapper(F("responded_at") - F("detected_at"), output_field=DurationField()),
    )

    return {
        "mttd": detection,
        "mttr": resolution,
        "mtta": response,
    }


def lifecycle_metrics_snapshot() -> dict[str, dict]:
    return {
        "overall": calculate_mttd_mttr(),
        "last_30_days": calculate_mttd_mttr(window=timedelta(days=30)),
    }


def humanize_duration(value):
    if not value:
        return None
    total_seconds = int(value.total_seconds())
    sign = "-" if total_seconds < 0 else ""
    total_seconds = abs(total_seconds)
    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    if not days and hours == 0:
        parts.append(f"{seconds}s")
    return f"{sign}{' '.join(parts)}"


def serialize_duration(value):
    if not value:
        return {"seconds": None, "iso": None, "display": None}
    total_seconds = value.total_seconds()
    sign = "-" if total_seconds < 0 else ""
    total_seconds_abs = abs(int(total_seconds))
    days, remainder = divmod(total_seconds_abs, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    iso = f"{sign}P{days}DT{hours}H{minutes}M{seconds}S"
    return {"seconds": total_seconds, "iso": iso, "display": humanize_duration(value)}
