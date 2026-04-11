from __future__ import annotations

import django_filters

from incidents.models import Incident


class IncidentFilter(django_filters.FilterSet):
    created_at_after = django_filters.IsoDateTimeFilter(field_name="created_at", lookup_expr="gte")
    created_at_before = django_filters.IsoDateTimeFilter(field_name="created_at", lookup_expr="lte")
    label = django_filters.CharFilter(method="filter_label")

    class Meta:
        model = Incident
        fields = ["severity", "status"]

    def filter_label(self, queryset, name, value):
        if not value:
            return queryset
        return queryset.filter(labels__contains=[value])
