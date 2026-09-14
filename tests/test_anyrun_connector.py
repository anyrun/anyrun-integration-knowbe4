import pytest

import anyrun_connector as anyrun_connector_module
from anyrun_connector import ANYRUN, UserLimits
from exceptions import AnyRunApiError, AnyRunParallelLimitError


class FakeSandboxConnector:
    def __init__(
        self,
        user_limits=None,
        task_id="task-123",
        run_download_error=None,
        status_events=None,
        verdict_results=None,
    ):
        self._user_limits = user_limits or {"parallels": {"total": 3, "available": 2}}
        self._task_id = task_id
        self._run_download_error = run_download_error
        self._status_events = (
            status_events if status_events is not None else ["running", "done"]
        )
        # verdict_results: list of return values / exceptions, consumed in order
        self._verdict_results = list(verdict_results or ["Malicious activity"])
        self.get_analysis_verdict_calls = 0

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get_user_limits(self):
        return self._user_limits

    def run_download_analysis(self, **kwargs):
        if self._run_download_error:
            raise self._run_download_error
        return self._task_id

    def get_task_status(self, task_uuid, simplify=True):
        return iter(self._status_events)

    def get_analysis_verdict(self, task_uuid):
        self.get_analysis_verdict_calls += 1
        result = self._verdict_results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


@pytest.fixture
def anyrun():
    return ANYRUN()


def _patch_connector(monkeypatch, fake_connector):
    monkeypatch.setattr(
        anyrun_connector_module.ANYRUN, "_connector", lambda self: fake_connector
    )


class TestGetParallelLimits:
    def test_returns_user_limits(self, anyrun, monkeypatch):
        fake = FakeSandboxConnector(
            user_limits={"parallels": {"total": 5, "available": 4}}
        )
        _patch_connector(monkeypatch, fake)

        limits = anyrun.get_parallel_limits()

        assert limits == UserLimits(total=5, available=4)

    def test_wraps_errors(self, anyrun, monkeypatch):
        class Boom(FakeSandboxConnector):
            def get_user_limits(self):
                raise RuntimeError("network down")

        _patch_connector(monkeypatch, Boom())

        with pytest.raises(AnyRunApiError):
            anyrun.get_parallel_limits()


class TestSubmitDownload:
    def test_returns_task_id(self, anyrun, monkeypatch):
        fake = FakeSandboxConnector(task_id="abc-123")
        _patch_connector(monkeypatch, fake)

        task_id = anyrun.submit_download("https://example.com/e.eml")

        assert task_id == "abc-123"

    def test_raises_parallel_limit_error(self, anyrun, monkeypatch):
        fake = FakeSandboxConnector(
            run_download_error=RuntimeError("Parallel tasks limit exceeded")
        )
        _patch_connector(monkeypatch, fake)

        with pytest.raises(AnyRunParallelLimitError):
            anyrun.submit_download("https://example.com/e.eml")

    def test_raises_generic_api_error_for_unrelated_failures(self, anyrun, monkeypatch):
        fake = FakeSandboxConnector(run_download_error=RuntimeError("boom"))
        _patch_connector(monkeypatch, fake)

        with pytest.raises(AnyRunApiError):
            anyrun.submit_download("https://example.com/e.eml")


class TestWaitForVerdict:
    def test_returns_verdict_on_first_attempt(self, anyrun, monkeypatch):
        fake = FakeSandboxConnector(verdict_results=["No threats detected"])
        _patch_connector(monkeypatch, fake)

        verdict = anyrun.wait_for_verdict("task-1")

        assert verdict == "No threats detected"
        assert fake.get_analysis_verdict_calls == 1

    def test_retries_transient_failure_then_succeeds(self, anyrun, monkeypatch):
        monkeypatch.setattr(anyrun_connector_module, "ANYRUN_VERDICT_RETRY_ATTEMPTS", 3)
        monkeypatch.setattr(
            anyrun_connector_module, "ANYRUN_VERDICT_RETRY_DELAY_SECONDS", 0
        )
        monkeypatch.setattr(anyrun_connector_module.time, "sleep", lambda _: None)

        fake = FakeSandboxConnector(
            verdict_results=[
                AttributeError("'NoneType' object has no attribute 'get'"),
                AttributeError("'NoneType' object has no attribute 'get'"),
                "Malicious activity",
            ]
        )
        _patch_connector(monkeypatch, fake)

        verdict = anyrun.wait_for_verdict("task-1")

        assert verdict == "Malicious activity"
        assert fake.get_analysis_verdict_calls == 3

    def test_exhausts_retries_and_raises_api_error(self, anyrun, monkeypatch):
        monkeypatch.setattr(anyrun_connector_module, "ANYRUN_VERDICT_RETRY_ATTEMPTS", 3)
        monkeypatch.setattr(
            anyrun_connector_module, "ANYRUN_VERDICT_RETRY_DELAY_SECONDS", 0
        )
        monkeypatch.setattr(anyrun_connector_module.time, "sleep", lambda _: None)

        fake = FakeSandboxConnector(
            verdict_results=[
                AttributeError("boom"),
                AttributeError("boom"),
                AttributeError("boom"),
            ]
        )
        _patch_connector(monkeypatch, fake)

        with pytest.raises(AnyRunApiError):
            anyrun.wait_for_verdict("task-1")

        assert fake.get_analysis_verdict_calls == 3


class TestReportUrl:
    def test_formats_task_id_into_prefix(self, anyrun):
        anyrun.report_prefix = "https://app.any.run/tasks/"
        assert anyrun.report_url("abc-123") == "https://app.any.run/tasks/abc-123"


class TestConnectorFactory:
    def test_dispatches_to_factory_matching_os_type(self, anyrun, monkeypatch):
        calls = []
        anyrun.os_type = "linux"
        monkeypatch.setitem(
            anyrun_connector_module._CONNECTOR_FACTORIES,
            "linux",
            lambda **kwargs: calls.append(kwargs) or "linux-connector",
        )

        result = anyrun._connector()

        assert result == "linux-connector"
        assert calls[0]["api_key"] == anyrun.api_key

    def test_passes_proxy_settings_through(self, anyrun, monkeypatch):
        captured = {}
        monkeypatch.setattr(
            anyrun_connector_module,
            "HTTP_PROXY_URL",
            "http://proxy.company.local:3128",
        )
        monkeypatch.setitem(
            anyrun_connector_module._CONNECTOR_FACTORIES,
            "windows",
            lambda **kwargs: captured.update(kwargs),
        )

        anyrun._connector()

        assert captured["proxy"] == "http://proxy.company.local:3128"

    def test_no_proxy_configured_passes_none(self, anyrun, monkeypatch):
        captured = {}
        monkeypatch.setattr(anyrun_connector_module, "HTTP_PROXY_URL", None)
        monkeypatch.setitem(
            anyrun_connector_module._CONNECTOR_FACTORIES,
            "windows",
            lambda **kwargs: captured.update(kwargs),
        )

        anyrun._connector()

        assert captured["proxy"] is None


class TestSubmitKwargs:
    def test_windows_includes_env_version_bitness_and_type(self, anyrun):
        anyrun.os_type = "windows"
        kwargs = anyrun._submit_kwargs("https://example.com/e.eml")

        assert "env_version" in kwargs
        assert "env_bitness" in kwargs
        assert "env_type" in kwargs
        assert "env_os" not in kwargs

    def test_linux_includes_env_os_instead_of_windows_fields(self, anyrun, monkeypatch):
        anyrun.os_type = "linux"
        monkeypatch.setattr(anyrun_connector_module, "ANYRUN_LINUX_ENV_OS", "ubuntu")

        kwargs = anyrun._submit_kwargs("https://example.com/e.eml")

        assert kwargs["env_os"] == "ubuntu"
        assert "env_version" not in kwargs
        assert "env_bitness" not in kwargs
        assert "env_type" not in kwargs

    def test_macos_has_no_os_version_fields(self, anyrun):
        anyrun.os_type = "macos"
        kwargs = anyrun._submit_kwargs("https://example.com/e.eml")

        assert "env_os" not in kwargs
        assert "env_version" not in kwargs
        assert "env_bitness" not in kwargs
        assert "env_type" not in kwargs
