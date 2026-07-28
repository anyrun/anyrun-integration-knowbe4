from const import INGESTION_TAG
from message import Message, Tag


def _raw_message(**overrides) -> dict:
    base = {
        "id": "msg-1",
        "rawUrl": "https://example.com/e.eml",
        "pipelineStatus": "PROCESSED",
        "actionStatus": "open",
        "tags": [],
        "events": [],
    }
    base.update(overrides)
    return base


class TestTag:
    def test_equal_by_name_ignores_type(self):
        assert Tag(name="ANYRUN_QUEUED", type="user") == Tag(
            name="ANYRUN_QUEUED", type="system"
        )

    def test_not_equal_when_name_differs(self):
        assert Tag(name="ANYRUN_QUEUED") != Tag(name="ANYRUN_PENDING")

    def test_hashable_by_name(self):
        assert hash(Tag(name="X", type="a")) == hash(Tag(name="X", type="b"))


class TestMessageAnyrunTagDetection:
    def test_no_anyrun_tag(self):
        msg = Message(_raw_message(tags=[{"name": "SOME_OTHER_TAG", "type": "user"}]))
        assert msg.has_anyrun_tag is False

    def test_has_anyrun_tag(self):
        msg = Message(_raw_message(tags=[{"name": "ANYRUN_QUEUED", "type": "system"}]))
        assert msg.has_anyrun_tag is True

    def test_ingestion_tag_alone_is_not_treated_as_an_anyrun_tag(self):
        # INGESTION_TAG (e.g. ANYRUN_REQUEST) lives in the ANYRUN_* namespace
        # but is the trigger a user applies to request scanning, not a sign
        # of prior/ongoing processing - it must not block its own ingestion.
        msg = Message(
            _raw_message(tags=[{"name": INGESTION_TAG, "type": "user"}])
        )
        assert msg.has_anyrun_tag is False

    def test_ingestion_tag_alongside_a_real_anyrun_tag_still_counts(self):
        msg = Message(
            _raw_message(
                tags=[
                    {"name": INGESTION_TAG, "type": "user"},
                    {"name": "ANYRUN_SCANNED", "type": "system"},
                ]
            )
        )
        assert msg.has_anyrun_tag is True

    def test_action_status_is_uppercased(self):
        msg = Message(_raw_message(actionStatus="resolved"))
        assert msg.action_status == "RESOLVED"


class TestInjectTags:
    def test_appends_new_tags(self):
        msg = Message(_raw_message())
        msg.inject_tags([Tag(name="ANYRUN_QUEUED")])
        assert [t.name for t in msg.tags] == ["ANYRUN_QUEUED"]

    def test_does_not_duplicate_existing_tag(self):
        msg = Message(_raw_message(tags=[{"name": "ANYRUN_QUEUED", "type": "system"}]))
        msg.inject_tags([Tag(name="ANYRUN_QUEUED")])
        assert [t.name for t in msg.tags] == ["ANYRUN_QUEUED"]


class TestEraseTags:
    def test_removes_only_named_tags(self):
        msg = Message(
            _raw_message(
                tags=[
                    {"name": "ANYRUN_QUEUED", "type": "system"},
                    {"name": "ANYRUN_REQUEST", "type": "user"},
                    {"name": "ANYRUN_PENDING", "type": "system"},
                ]
            )
        )

        msg.erase_tags([Tag(name="ANYRUN_QUEUED"), Tag(name="ANYRUN_REQUEST")])

        assert [t.name for t in msg.tags] == ["ANYRUN_PENDING"]

    def test_removing_multiple_tags_does_not_duplicate_survivors(self):
        # Regression test: an earlier implementation re-appended each
        # surviving tag once per removed tag when more than one tag was
        # removed at a time, producing duplicates.
        msg = Message(
            _raw_message(
                tags=[
                    {"name": "KEEP_ME", "type": "user"},
                    {"name": "REMOVE_A", "type": "system"},
                    {"name": "REMOVE_B", "type": "system"},
                ]
            )
        )

        msg.erase_tags([Tag(name="REMOVE_A"), Tag(name="REMOVE_B")])

        assert [t.name for t in msg.tags] == ["KEEP_ME"]
