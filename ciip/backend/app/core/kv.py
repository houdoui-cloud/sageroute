"""Small key/value facade over Redis with an in-memory fallback.

Used for JWT revocation, rate limiting and short-lived caches. The fallback keeps
tests and single-process development working without a Redis server.
"""

import threading
import time
from typing import Protocol

from app.core.config import get_settings


class KV(Protocol):
    def get(self, key: str) -> str | None: ...
    def set(self, key: str, value: str, ttl: int) -> None: ...
    def incr(self, key: str, ttl: int) -> int: ...
    def delete_prefix(self, prefix: str) -> None: ...


class MemoryKV:
    def __init__(self) -> None:
        self._data: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()

    def _alive(self, key: str) -> tuple[str, float] | None:
        item = self._data.get(key)
        if item and item[1] < time.time():
            self._data.pop(key, None)
            return None
        return item

    def get(self, key: str) -> str | None:
        with self._lock:
            item = self._alive(key)
            return item[0] if item else None

    def set(self, key: str, value: str, ttl: int) -> None:
        with self._lock:
            self._data[key] = (value, time.time() + ttl)

    def incr(self, key: str, ttl: int) -> int:
        with self._lock:
            item = self._alive(key)
            if item is None:
                self._data[key] = ("1", time.time() + ttl)
                return 1
            value = int(item[0]) + 1
            self._data[key] = (str(value), item[1])
            return value

    def delete_prefix(self, prefix: str) -> None:
        with self._lock:
            for key in [k for k in self._data if k.startswith(prefix)]:
                del self._data[key]


class RedisKV:
    def __init__(self, url: str) -> None:
        import redis

        self._r = redis.Redis.from_url(url, decode_responses=True, socket_timeout=2)
        self._r.ping()

    def get(self, key: str) -> str | None:
        return self._r.get(key)

    def set(self, key: str, value: str, ttl: int) -> None:
        self._r.set(key, value, ex=max(ttl, 1))

    def incr(self, key: str, ttl: int) -> int:
        pipe = self._r.pipeline()
        pipe.incr(key)
        pipe.expire(key, ttl, nx=True)
        return int(pipe.execute()[0])

    def delete_prefix(self, prefix: str) -> None:
        for key in self._r.scan_iter(match=f"{prefix}*"):
            self._r.delete(key)


_kv: KV | None = None


def get_kv() -> KV:
    global _kv
    if _kv is None:
        url = get_settings().redis_url
        if url:
            try:
                _kv = RedisKV(url)
            except Exception:  # noqa: BLE001 - degrade gracefully, logged at startup
                _kv = MemoryKV()
        else:
            _kv = MemoryKV()
    return _kv


def set_kv(kv: KV) -> None:
    global _kv
    _kv = kv
