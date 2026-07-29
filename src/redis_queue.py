import time
from typing import List, Literal, Tuple

from redis import Redis

from const import (
    PROCESSED_TTL_SECONDS,
    QUEUE_SAFETY_TTL_SECONDS,
    REDIS_DB,
    REDIS_HOST,
    REDIS_PORT,
)
from exceptions import RedisError
from message import Message


class Queue:
    def __init__(self) -> None:
        self.redis = Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            db=REDIS_DB,
            decode_responses=True,
        )

        self.message_queue_prefix = "msgs:"
        self.inprogress_queue_prefix = "inprogress:"
        self.processed_queue_prefix = "processed:"
        # Redis hash: message_id -> PhishER CREATED event timestamp (unix
        # seconds). Kept separate from the msgs:/inprogress: key values
        # (which track *our* insertion time, used for staleness detection),
        # so ordering by original report time doesn't interfere with that.
        self.created_at_key = "created_at"

    def _key(self, prefix: str, message_id: str) -> str:
        return f"{prefix}{message_id}"

    @staticmethod
    def _now_ms() -> str:
        return str(int(time.time() * 1000))

    @staticmethod
    def _now_seconds() -> int:
        return int(time.time())

    def _set(self, key: str, ttl: int | None) -> bool:
        try:
            return bool(self.redis.set(name=key, value=self._now_ms(), ex=ttl))
        except Exception as e:
            raise RedisError(f"Can't set key '{key}' in Redis: {e}")

    def _delete(self, key: str) -> None:
        try:
            self.redis.delete(key)
        except Exception as e:
            raise RedisError(f"Can't delete key '{key}' in Redis: {e}")

    def _keys_with_timestamps(self, prefix: str) -> List[Tuple[str, int]]:
        try:
            keys = list(self.redis.scan_iter(match=f"{prefix}*"))
            if not keys:
                return []

            values = self.redis.mget(keys)
        except Exception as e:
            raise RedisError(f"Can't scan keys with prefix '{prefix}': {e}")

        entries = []
        for key, value in zip(keys, values):
            message_id = key[len(prefix) :]
            timestamp = int(value) if value else 0
            entries.append((message_id, timestamp))

        return entries

    def _find_message_prefixes(self, message_id: str) -> List[str]:
        prefixes = []
        for prefix in (
            self.message_queue_prefix,
            self.inprogress_queue_prefix,
            self.processed_queue_prefix,
        ):
            try:
                if self.redis.exists(self._key(prefix, message_id)):
                    prefixes.append(prefix)
            except Exception as e:
                raise RedisError(f"Can't check key existence in Redis: {e}")

        return prefixes

    def _find_active_prefixes(self, message_id: str) -> List[str]:
        """Prefixes among msgs:/inprogress: that already hold this message.

        processed: is intentionally excluded here: if an admin re-applies the
        ingestion tag to a message that was already scanned before, that's a
        request for a fresh analysis, not something to silently skip just
        because a `processed:` marker is still sitting in Redis.
        """
        prefixes = []
        for prefix in (self.message_queue_prefix, self.inprogress_queue_prefix):
            try:
                if self.redis.exists(self._key(prefix, message_id)):
                    prefixes.append(prefix)
            except Exception as e:
                raise RedisError(f"Can't check key existence in Redis: {e}")

        return prefixes

    def is_queued(self, message_id: str) -> bool:
        return len(self._find_message_prefixes(message_id)) > 0

    def enqueue_message(self, message: Message) -> tuple[bool, str]:
        existing = self._find_active_prefixes(message.message_id)
        if existing:
            return (
                False,
                f"Message already in Redis. In `{', '.join(existing)}` queue(s)",
            )

        queue_key = self._key(self.message_queue_prefix, message.message_id)
        result = self._set(queue_key, ttl=QUEUE_SAFETY_TTL_SECONDS)

        if not result:
            return False, "Message was not enqueued due to unexpected error"

        self._set_created_at(message)
        return True, "Message was successfully enqueued"

    def _set_created_at(self, message: Message) -> None:
        created_at = message.created_at_timestamp()
        if created_at is None:
            created_at = self._now_seconds()

        try:
            self.redis.hset(self.created_at_key, message.message_id, created_at)
        except Exception as e:
            raise RedisError(
                f"Can't set created_at for '{message.message_id}' in Redis: {e}"
            )

    def _delete_created_at(self, message_id: str) -> None:
        try:
            self.redis.hdel(self.created_at_key, message_id)
        except Exception as e:
            raise RedisError(
                f"Can't delete created_at for '{message_id}' in Redis: {e}"
            )

    def fetch_with_order(self, order: Literal["asc", "desc"] = "asc") -> List[str]:
        """Return currently queued message_ids ordered by PhishER CREATED time.

        Sorting uses the created_at hash cached at enqueue time, so no
        PhishER API calls are needed just to determine processing order -
        only the messages actually picked for this batch get their full
        message fetched afterward (by the caller, per message, right before
        processing it).
        """
        message_ids = [
            message_id
            for message_id, _ in self._keys_with_timestamps(self.message_queue_prefix)
        ]
        if not message_ids:
            return []

        try:
            created_at_values = self.redis.hmget(self.created_at_key, message_ids)
        except Exception as e:
            raise RedisError(f"Can't read created_at values from Redis: {e}")

        entries = [
            (message_id, int(created_at) if created_at else 0)
            for message_id, created_at in zip(message_ids, created_at_values)
        ]
        entries.sort(key=lambda entry: entry[1], reverse=(order == "desc"))

        return [message_id for message_id, _ in entries]

    def claim_message(self, message_id: str) -> bool:
        msg_key = self._key(self.message_queue_prefix, message_id)
        inprogress_key = self._key(self.inprogress_queue_prefix, message_id)

        try:
            claimed = self.redis.getdel(msg_key)
        except Exception as e:
            raise RedisError(f"Can't claim key '{msg_key}' in Redis: {e}")

        if claimed is None:
            return False

        self._set(inprogress_key, ttl=QUEUE_SAFETY_TTL_SECONDS)
        return True

    def finish_processing(self, message_id: str) -> None:
        inprogress_key = self._key(self.inprogress_queue_prefix, message_id)
        processed_key = self._key(self.processed_queue_prefix, message_id)

        self._set(processed_key, ttl=PROCESSED_TTL_SECONDS)
        self._delete(inprogress_key)
        self._delete_created_at(message_id)

    def drop_message(self, message_id: str) -> None:
        for prefix in (self.message_queue_prefix, self.inprogress_queue_prefix):
            self._delete(self._key(prefix, message_id))
        self._delete_created_at(message_id)

    def get_stale_messages(self, prefix: str, older_than_seconds: int) -> List[str]:
        now_ms = int(time.time() * 1000)
        threshold_ms = older_than_seconds * 1000

        return [
            message_id
            for message_id, timestamp in self._keys_with_timestamps(prefix)
            if timestamp and (now_ms - timestamp) > threshold_ms
        ]
