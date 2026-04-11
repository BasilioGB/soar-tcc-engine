from __future__ import annotations

from typing import Any

from django.core.exceptions import ImproperlyConfigured


def build_default_cache_config(
    *,
    cache_url: str | None = None,
    redis_url: str | None = None,
    fallback_url: str | None = None,
) -> dict[str, dict[str, Any]]:
    redis_location = _pick_redis_location(cache_url, redis_url, fallback_url)
    if redis_location:
        return {
            "default": {
                "BACKEND": "django.core.cache.backends.redis.RedisCache",
                "LOCATION": redis_location,
            }
        }

    raise ImproperlyConfigured(
        "Shared cache configuration is required. Configure CACHE_URL, REDIS_URL, "
        "or CELERY_BROKER_URL with a redis:// or rediss:// URL."
    )


def _pick_redis_location(*candidates: str | None) -> str | None:
    for candidate in candidates:
        value = (candidate or "").strip()
        if value.startswith(("redis://", "rediss://")):
            return value
    return None
