import pytest

import phisher as phisher_module
from exceptions import InvalidMessage, PhisherRequestError
from message import Message
from phisher import Phisher


class FakeResponse:
    def __init__(self, json_data: dict, status_ok: bool = True):
        self._json_data = json_data
        self._status_ok = status_ok

    def raise_for_status(self) -> None:
        if not self._status_ok:
            raise RuntimeError("HTTP error")

    def json(self) -> dict:
        return self._json_data


@pytest.fixture
def phisher():
    with Phisher() as p:
        yield p


def _raw_message(message_id: str = "msg-1", tags=None) -> dict:
    return {
        "id": message_id,
        "rawUrl": "https://example.com/e.eml",
        "pipelineStatus": "PROCESSED",
        "actionStatus": "open",
        "tags": tags or [],
        "events": [{"eventType": "CREATED", "createdAt": "2026-01-01T00:00:00Z"}],
    }


class TestListMessages:
    def test_parses_nodes_and_pagination(self, phisher):
        phisher._session.request = lambda **kwargs: FakeResponse(
            {
                "data": {
                    "phisherMessages": {
                        "nodes": [_raw_message("a"), _raw_message("b")],
                        "pagination": {
                            "page": 1,
                            "pages": 1,
                            "per": 50,
                            "totalCount": 2,
                        },
                    }
                }
            }
        )

        messages, pagination = phisher.list_messages(page=1)

        assert [m.message_id for m in messages] == ["a", "b"]
        assert pagination["totalCount"] == 2

    def test_uses_explicit_query_and_per_over_defaults(self, phisher):
        captured = {}

        def fake_request(**kwargs):
            captured["variables"] = kwargs["json"]["variables"]
            return FakeResponse(
                {
                    "data": {
                        "phisherMessages": {
                            "nodes": [],
                            "pagination": {
                                "page": 1,
                                "pages": 1,
                                "per": 5,
                                "totalCount": 0,
                            },
                        }
                    }
                }
            )

        phisher._session.request = fake_request

        phisher.list_messages(page=2, query='tags:"FOO"', per=5)

        assert captured["variables"]["query"] == 'tags:"FOO"'
        assert captured["variables"]["per"] == 5
        assert captured["variables"]["page"] == 2


class TestGetMessage:
    def test_parses_single_message(self, phisher):
        phisher._session.request = lambda **kwargs: FakeResponse(
            {"data": {"phisherMessage": _raw_message("solo")}}
        )

        message = phisher.get_message("solo")

        assert message.message_id == "solo"

    def test_raises_invalid_message_on_malformed_payload(self, phisher):
        # "tags" must be a list of {name, type} dicts; a string blows up
        # Tag(**tag) inside Message.__init__, which get_message must
        # translate into InvalidMessage rather than let leak through raw.
        phisher._session.request = lambda **kwargs: FakeResponse(
            {"data": {"phisherMessage": {"tags": "not-a-list"}}}
        )

        with pytest.raises(InvalidMessage):
            phisher.get_message("bad")


class TestAddTags:
    def test_sends_tag_names_and_updates_local_message(self, phisher):
        message = Message(_raw_message())
        captured = {}

        def fake_request(**kwargs):
            captured["variables"] = kwargs["json"]["variables"]
            return FakeResponse(
                {
                    "data": {
                        "phisherTagsCreate": {
                            "nodes": [{"name": "ANYRUN_QUEUED", "type": "system"}],
                            "errors": [],
                        }
                    }
                }
            )

        phisher._session.request = fake_request

        phisher.add_tags(message, ["ANYRUN_QUEUED"])

        assert captured["variables"]["tags"] == ["ANYRUN_QUEUED"]
        assert [t.name for t in message.tags] == ["ANYRUN_QUEUED"]

    def test_noop_on_empty_tag_list(self, phisher):
        message = Message(_raw_message())
        phisher._session.request = lambda **kwargs: (_ for _ in ()).throw(
            AssertionError("should not be called")
        )

        phisher.add_tags(message, [])  # must not raise / not call the API

    def test_raises_on_graphql_errors(self, phisher):
        message = Message(_raw_message())
        phisher._session.request = lambda **kwargs: FakeResponse(
            {
                "data": {
                    "phisherTagsCreate": {
                        "nodes": [],
                        "errors": [{"field": "tags", "reason": "invalid"}],
                    }
                }
            }
        )

        with pytest.raises(PhisherRequestError):
            phisher.add_tags(message, ["BAD_TAG"])


class TestRemoveTags:
    def test_updates_local_message(self, phisher):
        message = Message(
            _raw_message(tags=[{"name": "ANYRUN_QUEUED", "type": "system"}])
        )
        phisher._session.request = lambda **kwargs: FakeResponse(
            {"data": {"phisherTagsDelete": {"nodes": [], "errors": []}}}
        )

        phisher.remove_tags(message, ["ANYRUN_QUEUED"])

        assert message.tags == []


class TestSetCategory:
    def test_sends_category_in_payload(self, phisher):
        message = Message(_raw_message())
        captured = {}

        def fake_request(**kwargs):
            captured["variables"] = kwargs["json"]["variables"]
            return FakeResponse(
                {
                    "data": {
                        "phisherMessageUpdate": {
                            "node": {"id": message.message_id},
                            "errors": [],
                        }
                    }
                }
            )

        phisher._session.request = fake_request

        phisher.set_category(message, "THREAT")

        assert captured["variables"]["id"] == message.message_id
        assert captured["variables"]["payload"] == {"category": "THREAT"}

    def test_raises_on_graphql_errors(self, phisher):
        message = Message(_raw_message())
        phisher._session.request = lambda **kwargs: FakeResponse(
            {
                "data": {
                    "phisherMessageUpdate": {
                        "node": None,
                        "errors": [{"field": "category", "reason": "invalid"}],
                    }
                }
            }
        )

        with pytest.raises(PhisherRequestError):
            phisher.set_category(message, "THREAT")


class TestAddComment:
    def test_success(self, phisher):
        message = Message(_raw_message())
        phisher._session.request = lambda **kwargs: FakeResponse(
            {
                "data": {
                    "phisherCommentCreate": {
                        "node": {"body": "hi", "createdAt": "now"},
                        "errors": [],
                    }
                }
            }
        )

        phisher.add_comment(message, "hi")  # must not raise

    def test_raises_on_graphql_errors(self, phisher):
        message = Message(_raw_message())
        phisher._session.request = lambda **kwargs: FakeResponse(
            {
                "data": {
                    "phisherCommentCreate": {
                        "node": None,
                        "errors": [{"field": "comment", "reason": "too long"}],
                    }
                }
            }
        )

        with pytest.raises(PhisherRequestError):
            phisher.add_comment(message, "hi")


class TestProxy:
    def test_no_proxy_by_default(self):
        with Phisher() as p:
            assert p._session.proxies == {}

    def test_uses_http_proxy_when_configured(self, monkeypatch):
        monkeypatch.setattr(
            phisher_module,
            "HTTP_PROXY_URL",
            "http://user:pass@proxy.company.local:3128",
        )

        with Phisher() as p:
            assert p._session.proxies == {
                "http": "http://user:pass@proxy.company.local:3128",
                "https": "http://user:pass@proxy.company.local:3128",
            }


class TestMakeRequestErrorHandling:
    def test_wraps_transport_errors(self, phisher):
        def boom(**kwargs):
            raise ConnectionError("no route to host")

        phisher._session.request = boom

        with pytest.raises(PhisherRequestError):
            phisher.get_message("whatever")

    def test_wraps_http_error_status(self, phisher):
        phisher._session.request = lambda **kwargs: FakeResponse({}, status_ok=False)

        with pytest.raises(PhisherRequestError):
            phisher.get_message("whatever")
