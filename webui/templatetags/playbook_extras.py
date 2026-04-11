from __future__ import annotations

import json

from django import template

register = template.Library()

@register.filter
def dict_get(value, key):
    if value is None:
        return None
    try:
        return value.get(key)
    except AttributeError:
        return None


@register.filter
def pretty_json(value):
    try:
        return json.dumps(value, ensure_ascii=False, indent=2)
    except TypeError:
        return str(value)
