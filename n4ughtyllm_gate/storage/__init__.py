"""Storage backend selection helpers."""

from __future__ import annotations

from n4ughtyllm_gate.config.settings import settings
from n4ughtyllm_gate.storage.kv import KVStore
from n4ughtyllm_gate.storage.postgres_store import PostgresKVStore
from n4ughtyllm_gate.storage.redis_store import RedisKVStore
from n4ughtyllm_gate.storage.sqlite_store import SqliteKVStore


def create_store() -> KVStore:
    backend = settings.storage_backend.strip().lower()
    if backend == "redis":
        return RedisKVStore(redis_url=settings.redis_url, key_prefix=settings.redis_key_prefix)
    if backend in {"postgres", "postgresql"}:
        return PostgresKVStore(
            dsn=settings.postgres_dsn,
            schema=settings.postgres_schema,
        )
    return SqliteKVStore(db_path=settings.sqlite_db_path)
