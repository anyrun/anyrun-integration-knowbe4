from unittest.mock import MagicMock

import pytest

import connector as connector_module
from anyrun_connector import UserLimits
from connector import Connector
from exceptions import AnyRunParallelLimitError
from message import Message
from tags import Tags


def _raw_message(message_id: str = "msg-1", tags=None, **overrides) -> dict:
    base = {
        "id": message_id,
        "rawUrl": "https://example.com/e.eml",
        "pipelineStatus": "PROCESSED",
        "actionStatus": "open",
        "tags": tags or [],
        "events": [],
    }
    base.update(overrides)
    return base


class _PhisherContext:
    """Makes a plain mock usable as `with Phisher() as phisher:`."""

    def __init__(self, instance):
        self._instance = instance

    def __enter__(self):
        return self._instance

    def __exit__(self, *exc):
        return False


@pytest.fixture
def fake_phisher(monkeypatch):
    instance = MagicMock(name="phisher")
    monkeypatch.setattr(connector_module, "Phisher", lambda: _PhisherContext(instance))
    return instance


@pytest.fixture
def conn(fake_phisher):
    c = Connector()
    c.anyrun = MagicMock(name="anyrun")
    c.queue = MagicMock(name="queue")
    return c


class TestIngest:
    def test_enqueues_eligible_message_and_tags_queued(self, conn, fake_phisher):
        message = Message(_raw_message())
        fake_phisher.list_messages.return_value = ([message], {"pages": 1})
        conn.queue.enqueue_message.return_value = (True, "ok")

        conn.ingest()

        conn.queue.enqueue_message.assert_called_once_with(message)
        fake_phisher.add_tags.assert_called_once_with(message, [Tags.anyrun_queued])

    def test_skips_message_not_yet_processed(self, conn, fake_phisher):
        message = Message(_raw_message(pipelineStatus="ANALYZING"))
        fake_phisher.list_messages.return_value = ([message], {"pages": 1})

        conn.ingest()

        conn.queue.enqueue_message.assert_not_called()
        fake_phisher.add_tags.assert_not_called()

    def test_skips_resolved_message(self, conn, fake_phisher):
        message = Message(_raw_message(actionStatus="resolved"))
        fake_phisher.list_messages.return_value = ([message], {"pages": 1})

        conn.ingest()

        conn.queue.enqueue_message.assert_not_called()

    def test_skips_message_with_existing_anyrun_tag(self, conn, fake_phisher):
        message = Message(
            _raw_message(tags=[{"name": "ANYRUN_SCANNED", "type": "system"}])
        )
        fake_phisher.list_messages.return_value = ([message], {"pages": 1})

        conn.ingest()

        conn.queue.enqueue_message.assert_not_called()

    def test_skips_tagging_when_enqueue_rejected(self, conn, fake_phisher):
        message = Message(_raw_message())
        fake_phisher.list_messages.return_value = ([message], {"pages": 1})
        conn.queue.enqueue_message.return_value = (False, "already queued")

        conn.ingest()

        fake_phisher.add_tags.assert_not_called()

    def test_stops_after_last_page(self, conn, fake_phisher):
        message = Message(_raw_message())
        fake_phisher.list_messages.return_value = ([message], {"pages": 1})
        conn.queue.enqueue_message.return_value = (True, "ok")

        conn.ingest()

        assert fake_phisher.list_messages.call_count == 1


class TestProcess:
    def test_skips_when_nothing_queued(self, conn):
        conn.queue.get_queued_messages.return_value = []

        conn.process()

        conn.anyrun.submit_download_windows.assert_not_called()

    def test_processes_each_queued_message(self, conn, fake_phisher, monkeypatch):
        conn.queue.get_queued_messages.return_value = ["a", "b"]
        conn.anyrun.get_parallel_limits.return_value = UserLimits(total=5, available=5)
        calls = []
        monkeypatch.setattr(
            conn, "_process_one", lambda message_id: calls.append(message_id)
        )

        conn.process()

        assert calls == ["a", "b"]

    def test_one_message_failing_does_not_stop_the_others(
        self, conn, fake_phisher, monkeypatch
    ):
        conn.queue.get_queued_messages.return_value = ["a", "b"]
        conn.anyrun.get_parallel_limits.return_value = UserLimits(total=5, available=5)
        calls = []

        def fake_process_one(message_id):
            calls.append(message_id)
            if message_id == "a":
                raise RuntimeError("boom")

        monkeypatch.setattr(conn, "_process_one", fake_process_one)

        conn.process()  # must not raise

        assert calls == ["a", "b"]


class TestProcessOne:
    def test_happy_path_tags_scanned_and_finishes(self, conn, fake_phisher):
        message = Message(_raw_message())
        fake_phisher.get_message.return_value = message
        conn.queue.claim_message.return_value = True
        conn.anyrun.submit_download_windows.return_value = "task-1"
        conn.anyrun.wait_for_verdict.return_value = "Malicious activity"
        conn.anyrun.report_url.return_value = "https://app.any.run/tasks/task-1"

        conn._process_one(message.message_id)

        conn.queue.claim_message.assert_called_once_with(message.message_id)
        fake_phisher.add_tags.assert_any_call(message, [Tags.anyrun_pending])
        fake_phisher.remove_tags.assert_any_call(message, [Tags.anyrun_pending])
        fake_phisher.add_tags.assert_any_call(
            message, [Tags.anyrun_scanned, Tags.anyrun_malicious]
        )
        fake_phisher.add_comment.assert_called_once()
        conn.queue.finish_processing.assert_called_once_with(message.message_id)

    def test_ingestion_tag_is_dropped_alongside_queued(self, conn, fake_phisher, monkeypatch):
        monkeypatch.setattr(connector_module, "INGESTION_TAG", "SEND_TO_ANYRUN")
        message = Message(_raw_message())
        fake_phisher.get_message.return_value = message
        conn.queue.claim_message.return_value = True
        conn.anyrun.submit_download_windows.return_value = "task-1"
        conn.anyrun.wait_for_verdict.return_value = "clean"
        conn.anyrun.report_url.return_value = "url"

        conn._process_one(message.message_id)

        fake_phisher.remove_tags.assert_any_call(
            message, [Tags.anyrun_queued, "SEND_TO_ANYRUN"]
        )

    def test_resolved_message_is_dropped_without_submitting(self, conn, fake_phisher):
        message = Message(_raw_message(actionStatus="resolved"))
        fake_phisher.get_message.return_value = message

        conn._process_one(message.message_id)

        conn.queue.drop_message.assert_called_once_with(message.message_id)
        conn.anyrun.submit_download_windows.assert_not_called()
        conn.queue.claim_message.assert_not_called()

    def test_claim_failure_skips_processing(self, conn, fake_phisher):
        message = Message(_raw_message())
        fake_phisher.get_message.return_value = message
        conn.queue.claim_message.return_value = False

        conn._process_one(message.message_id)

        conn.anyrun.submit_download_windows.assert_not_called()

    def test_parallel_limit_error_requeues(self, conn, fake_phisher):
        message = Message(_raw_message())
        fake_phisher.get_message.return_value = message
        conn.queue.claim_message.return_value = True
        conn.anyrun.submit_download_windows.side_effect = AnyRunParallelLimitError("no slots")
        conn.queue.enqueue_message.return_value = (True, "ok")

        conn._process_one(message.message_id)

        conn.queue.drop_message.assert_called_once_with(message.message_id)
        conn.queue.enqueue_message.assert_called_once_with(message)
        fake_phisher.add_tags.assert_any_call(message, [Tags.anyrun_queued])

    def test_generic_failure_writes_error_state(self, conn, fake_phisher):
        message = Message(_raw_message())
        fake_phisher.get_message.return_value = message
        conn.queue.claim_message.return_value = True
        conn.anyrun.submit_download_windows.side_effect = RuntimeError("sandbox exploded")

        conn._process_one(message.message_id)

        conn.queue.drop_message.assert_called_once_with(message.message_id)
        fake_phisher.add_tags.assert_any_call(message, [Tags.anyrun_error])
        fake_phisher.add_comment.assert_called_once()
        assert "sandbox exploded" in fake_phisher.add_comment.call_args[0][1]

    def test_message_refresh_failure_leaves_message_queued(self, conn, fake_phisher):
        fake_phisher.get_message.side_effect = RuntimeError("PhishER unreachable")

        conn._process_one("msg-1")

        conn.queue.drop_message.assert_not_called()
        conn.queue.claim_message.assert_not_called()


class TestCleanup:
    def test_marks_stale_queue_messages_as_timeout(self, conn, fake_phisher):
        conn.queue.message_queue_prefix = "msgs:"
        conn.queue.inprogress_queue_prefix = "inprogress:"
        message = Message(_raw_message("stale-1"))

        def stale_side_effect(prefix, older_than_seconds):
            return ["stale-1"] if prefix == "msgs:" else []

        conn.queue.get_stale_messages.side_effect = stale_side_effect
        fake_phisher.get_message.return_value = message
        fake_phisher.list_messages.return_value = ([], {"pages": 1})

        conn.cleanup()

        conn.queue.drop_message.assert_any_call("stale-1")
        fake_phisher.add_tags.assert_any_call(message, [Tags.anyrun_timeout])
        fake_phisher.add_comment.assert_called_once()
        comment_text = fake_phisher.add_comment.call_args[0][1]
        assert "TIMEOUT" in comment_text

    def test_reconciles_orphaned_queued_tag_by_reenqueuing(self, conn, fake_phisher):
        conn.queue.get_stale_messages.return_value = []
        orphan = Message(
            _raw_message("orphan-1", tags=[{"name": "ANYRUN_QUEUED", "type": "system"}])
        )

        def list_messages_side_effect(page, query=None, per=None, sort_direction="DESCENDING"):
            if query == Tags.tag_query(Tags.anyrun_queued):
                return [orphan], {"pages": 1}
            return [], {"pages": 1}

        fake_phisher.list_messages.side_effect = list_messages_side_effect
        conn.queue.is_queued.return_value = False
        conn.queue.enqueue_message.return_value = (True, "ok")

        conn.cleanup()

        conn.queue.enqueue_message.assert_called_once_with(orphan)
        fake_phisher.add_tags.assert_any_call(orphan, [Tags.anyrun_queued])

    def test_does_not_touch_messages_still_genuinely_queued(self, conn, fake_phisher):
        conn.queue.get_stale_messages.return_value = []
        tracked = Message(
            _raw_message("tracked-1", tags=[{"name": "ANYRUN_QUEUED", "type": "system"}])
        )
        fake_phisher.list_messages.return_value = ([tracked], {"pages": 1})
        conn.queue.is_queued.return_value = True

        conn.cleanup()

        conn.queue.enqueue_message.assert_not_called()
