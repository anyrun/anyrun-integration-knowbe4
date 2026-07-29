import threading
import time as time_module

import fakeredis
import pytest

from message import Message
from redis_queue import Queue


def _raw_message(message_id: str, created_at: str | None = None) -> dict:
    events = []
    if created_at is not None:
        events.append({"eventType": "CREATED", "createdAt": created_at})

    return {
        "id": message_id,
        "rawUrl": "https://example.com/e.eml",
        "pipelineStatus": "PROCESSED",
        "actionStatus": "open",
        "tags": [],
        "events": events,
    }


@pytest.fixture
def queue() -> Queue:
    q = Queue()
    # Replace the real redis-py client with an in-memory fake so tests never
    # need a live Redis server.
    q.redis = fakeredis.FakeRedis(decode_responses=True)
    return q


@pytest.fixture
def message() -> Message:
    return Message(_raw_message("msg-1"))


class TestEnqueueMessage:
    def test_enqueues_new_message(self, queue, message):
        ok, reason = queue.enqueue_message(message)

        assert ok is True
        assert queue.redis.exists("msgs:msg-1")

    def test_rejects_duplicate_in_msgs(self, queue, message):
        queue.enqueue_message(message)

        ok, reason = queue.enqueue_message(message)

        assert ok is False
        assert "msgs:" in reason

    def test_rejects_duplicate_in_inprogress(self, queue, message):
        queue.enqueue_message(message)
        queue.claim_message(message.message_id)

        ok, reason = queue.enqueue_message(message)

        assert ok is False
        assert "inprogress:" in reason

    def test_allows_reenqueue_when_only_processed_marker_exists(self, queue, message):
        queue.enqueue_message(message)
        queue.claim_message(message.message_id)
        queue.finish_processing(message.message_id)
        assert queue.redis.exists("processed:msg-1")

        ok, reason = queue.enqueue_message(message)

        assert ok is True
        assert queue.redis.exists("msgs:msg-1")
        # the stale processed: marker is left alone, not treated as a blocker
        assert queue.redis.exists("processed:msg-1")


class TestClaimMessage:
    def test_claim_moves_msgs_key_to_inprogress(self, queue, message):
        queue.enqueue_message(message)

        claimed = queue.claim_message(message.message_id)

        assert claimed is True
        assert not queue.redis.exists("msgs:msg-1")
        assert queue.redis.exists("inprogress:msg-1")

    def test_claim_fails_when_nothing_queued(self, queue):
        assert queue.claim_message("does-not-exist") is False

    def test_claim_is_atomic_under_concurrency(self, queue, message):
        queue.enqueue_message(message)

        results = []

        def worker():
            results.append(queue.claim_message(message.message_id))

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert sum(1 for r in results if r) == 1


class TestFinishProcessing:
    def test_moves_inprogress_to_processed(self, queue, message):
        queue.enqueue_message(message)
        queue.claim_message(message.message_id)

        queue.finish_processing(message.message_id)

        assert not queue.redis.exists("inprogress:msg-1")
        assert queue.redis.exists("processed:msg-1")


class TestDropMessage:
    def test_removes_from_msgs_and_inprogress(self, queue, message):
        queue.enqueue_message(message)
        queue.claim_message(message.message_id)

        queue.drop_message(message.message_id)

        assert not queue.redis.exists("msgs:msg-1")
        assert not queue.redis.exists("inprogress:msg-1")

    def test_does_not_touch_processed(self, queue, message):
        queue.enqueue_message(message)
        queue.claim_message(message.message_id)
        queue.finish_processing(message.message_id)

        queue.drop_message(message.message_id)

        assert queue.redis.exists("processed:msg-1")


class TestIsQueued:
    def test_true_for_any_prefix_including_processed(self, queue, message):
        queue.enqueue_message(message)
        queue.claim_message(message.message_id)
        queue.finish_processing(message.message_id)

        assert queue.is_queued(message.message_id) is True

    def test_false_when_absent_everywhere(self, queue):
        assert queue.is_queued("nope") is False


class TestFetchWithOrder:
    def test_orders_by_phisher_created_event_ascending_by_default(self, queue):
        # Enqueued out of order; sort must follow the CREATED event time,
        # not insertion order.
        queue.enqueue_message(
            Message(_raw_message("third", created_at="2026-01-03T00:00:00Z"))
        )
        queue.enqueue_message(
            Message(_raw_message("first", created_at="2026-01-01T00:00:00Z"))
        )
        queue.enqueue_message(
            Message(_raw_message("second", created_at="2026-01-02T00:00:00Z"))
        )

        assert queue.fetch_with_order() == ["first", "second", "third"]

    def test_desc_order_reverses(self, queue):
        queue.enqueue_message(
            Message(_raw_message("first", created_at="2026-01-01T00:00:00Z"))
        )
        queue.enqueue_message(
            Message(_raw_message("second", created_at="2026-01-02T00:00:00Z"))
        )

        assert queue.fetch_with_order(order="desc") == ["second", "first"]

    def test_message_without_created_event_falls_back_to_now(self, queue, monkeypatch):
        monkeypatch.setattr(queue, "_now_seconds", lambda: 5000)
        queue.enqueue_message(Message(_raw_message("no-event")))

        created_at = queue.redis.hget(queue.created_at_key, "no-event")
        assert created_at == "5000"

    def test_empty_queue_returns_empty_list(self, queue):
        assert queue.fetch_with_order() == []

    def test_claimed_message_is_excluded(self, queue):
        queue.enqueue_message(
            Message(_raw_message("first", created_at="2026-01-01T00:00:00Z"))
        )
        queue.enqueue_message(
            Message(_raw_message("second", created_at="2026-01-02T00:00:00Z"))
        )
        queue.claim_message("first")

        assert queue.fetch_with_order() == ["second"]


class TestCreatedAtLifecycle:
    def test_finish_processing_removes_created_at_entry(self, queue, message):
        queue.enqueue_message(message)
        queue.claim_message(message.message_id)
        assert queue.redis.hexists(queue.created_at_key, message.message_id)

        queue.finish_processing(message.message_id)

        assert not queue.redis.hexists(queue.created_at_key, message.message_id)

    def test_drop_message_removes_created_at_entry(self, queue, message):
        queue.enqueue_message(message)
        assert queue.redis.hexists(queue.created_at_key, message.message_id)

        queue.drop_message(message.message_id)

        assert not queue.redis.hexists(queue.created_at_key, message.message_id)


class TestGetStaleMessages:
    def test_flags_messages_older_than_threshold(self, queue, monkeypatch):
        old_ts = int(time_module.time() * 1000) - 10_000
        monkeypatch.setattr(queue, "_now_ms", lambda: str(old_ts))
        queue.enqueue_message(Message(_raw_message("stale")))

        # restore real clock for the check itself
        monkeypatch.undo()

        stale = queue.get_stale_messages(queue.message_queue_prefix, older_than_seconds=5)

        assert stale == ["stale"]

    def test_does_not_flag_fresh_messages(self, queue, message):
        queue.enqueue_message(message)

        stale = queue.get_stale_messages(queue.message_queue_prefix, older_than_seconds=3600)

        assert stale == []
