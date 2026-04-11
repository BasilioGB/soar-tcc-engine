from __future__ import annotations

from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase

from core.cache_config import build_default_cache_config


class CacheConfigTests(SimpleTestCase):
    def test_uses_explicit_cache_url_when_present(self):
        config = build_default_cache_config(
            cache_url="redis://cache:6379/2",
            redis_url="redis://redis:6379/1",
            fallback_url="redis://broker:6379/0",
        )

        self.assertEqual(
            config["default"]["BACKEND"],
            "django.core.cache.backends.redis.RedisCache",
        )
        self.assertEqual(config["default"]["LOCATION"], "redis://cache:6379/2")

    def test_falls_back_to_redis_url(self):
        config = build_default_cache_config(
            cache_url="",
            redis_url="redis://redis:6379/1",
            fallback_url="redis://broker:6379/0",
        )

        self.assertEqual(
            config["default"]["BACKEND"],
            "django.core.cache.backends.redis.RedisCache",
        )
        self.assertEqual(config["default"]["LOCATION"], "redis://redis:6379/1")

    def test_falls_back_to_broker_url_when_it_is_redis(self):
        config = build_default_cache_config(
            cache_url="",
            redis_url="",
            fallback_url="redis://broker:6379/0",
        )

        self.assertEqual(
            config["default"]["BACKEND"],
            "django.core.cache.backends.redis.RedisCache",
        )
        self.assertEqual(config["default"]["LOCATION"], "redis://broker:6379/0")

    def test_raises_when_no_redis_url_exists(self):
        with self.assertRaisesMessage(
            ImproperlyConfigured,
            "Shared cache configuration is required.",
        ):
            build_default_cache_config(
                cache_url="",
                redis_url="memory://",
                fallback_url="memory://",
            )
