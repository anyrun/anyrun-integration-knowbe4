import logging
import time

from anyrun.connectors import SandboxConnector
from pydantic import BaseModel

from const import (
    ANYRUN_API_KEY,
    ANYRUN_AUTOMATED_INTERACTIVITY,
    ANYRUN_ENV_BITNESS,
    ANYRUN_ENV_LOCALE,
    ANYRUN_ENV_TYPE,
    ANYRUN_ENV_VERSION,
    ANYRUN_GEO,
    ANYRUN_LINUX_ENV_OS,
    ANYRUN_MITM,
    ANYRUN_OBJ_EXT_CMD,
    ANYRUN_OBJ_EXT_EXTENSION,
    ANYRUN_OBJ_EXT_STARTFOLDER,
    ANYRUN_OPT_NETWORK_CONNECT,
    ANYRUN_OPT_NETWORK_FAKENET,
    ANYRUN_OPT_TIMEOUT,
    ANYRUN_OS_TYPE,
    ANYRUN_PRIVACY_TYPE,
    ANYRUN_REPORT_PREFIX,
    ANYRUN_RESIDENTIAL_PROXY,
    ANYRUN_RESIDENTIAL_PROXY_GEO,
    ANYRUN_ROOT_URL,
    ANYRUN_TOR,
    ANYRUN_VERDICT_RETRY_ATTEMPTS,
    ANYRUN_VERDICT_RETRY_DELAY_SECONDS,
    HTTP_PROXY_URL,
    __version__,
)
from exceptions import AnyRunApiError, AnyRunParallelLimitError

logger = logging.getLogger(__name__)

_CONNECTOR_FACTORIES = {
    "windows": SandboxConnector.windows,
    "linux": SandboxConnector.linux,
    "macos": SandboxConnector.macos,
}


class UserLimits(BaseModel):
    total: int
    available: int


class ANYRUN:
    def __init__(self) -> None:
        self.api_key = ANYRUN_API_KEY
        self.os_type = ANYRUN_OS_TYPE
        self.root_url = ANYRUN_ROOT_URL
        self.report_prefix = ANYRUN_REPORT_PREFIX

        self.telemetry = f"KnowBe4PhishER:{__version__}"

    def _connector(self) -> SandboxConnector:
        # A fresh connector is created per call (instead of reusing one shared
        # instance) so concurrent worker threads never share SDK connection state.
        factory = _CONNECTOR_FACTORIES[self.os_type]
        return factory(
            api_key=self.api_key,
            integration=self.telemetry,
            root_url=self.root_url,
            proxy=HTTP_PROXY_URL,
        )

    def _submit_kwargs(self, url: str) -> dict:
        kwargs = dict(
            obj_url=url,
            env_locale=ANYRUN_ENV_LOCALE,
            opt_network_connect=ANYRUN_OPT_NETWORK_CONNECT,
            opt_network_fakenet=ANYRUN_OPT_NETWORK_FAKENET,
            opt_network_tor=ANYRUN_TOR,
            opt_network_geo=ANYRUN_GEO,
            opt_network_mitm=ANYRUN_MITM,
            opt_network_residential_proxy=ANYRUN_RESIDENTIAL_PROXY,
            opt_network_residential_proxy_geo=ANYRUN_RESIDENTIAL_PROXY_GEO,
            opt_privacy_type=ANYRUN_PRIVACY_TYPE,
            opt_timeout=ANYRUN_OPT_TIMEOUT,
            opt_automated_interactivity=ANYRUN_AUTOMATED_INTERACTIVITY,
            opt_privacy_hidesource=True,
            obj_ext_startfolder=ANYRUN_OBJ_EXT_STARTFOLDER,
            obj_ext_cmd=ANYRUN_OBJ_EXT_CMD or None,
            obj_ext_extension=ANYRUN_OBJ_EXT_EXTENSION,
        )

        if self.os_type == "windows":
            kwargs.update(
                env_version=ANYRUN_ENV_VERSION,
                env_bitness=ANYRUN_ENV_BITNESS,
                env_type=ANYRUN_ENV_TYPE,
            )
        elif self.os_type == "linux":
            kwargs.update(env_os=ANYRUN_LINUX_ENV_OS)

        return kwargs

    @staticmethod
    def _is_parallel_limit_error(error: Exception) -> bool:
        text = str(error).lower()
        return "parallel" in text and (
            "limit" in text or "maximum" in text or "quota" in text
        )

    @staticmethod
    def _get_verdict_with_retry(connector: SandboxConnector, task_id: str) -> str:
        """Retry fetching the verdict a few times.

        The status stream can report a task as finished slightly before the
        report is fully written server-side, so the first call(s) right after
        can hit missing/None fields instead of a real API error.
        """
        last_error: Exception | None = None

        for attempt in range(1, ANYRUN_VERDICT_RETRY_ATTEMPTS + 1):
            try:
                return connector.get_analysis_verdict(task_id)
            except Exception as e:
                last_error = e
                logger.warning(
                    "Verdict not available yet for ANY.RUN task %s (attempt %s/%s): %s",
                    task_id,
                    attempt,
                    ANYRUN_VERDICT_RETRY_ATTEMPTS,
                    e,
                )
                if attempt < ANYRUN_VERDICT_RETRY_ATTEMPTS:
                    time.sleep(ANYRUN_VERDICT_RETRY_DELAY_SECONDS)

        raise last_error

    def get_parallel_limits(self) -> UserLimits:
        try:
            with self._connector() as connector:
                envs = connector.get_user_limits()
                parallels = envs.get("parallels", {})

                total, available = (
                    parallels.get("total", 0),
                    parallels.get("available", 0),
                )

                return UserLimits(total=total, available=available)
        except Exception as e:
            raise AnyRunApiError(f"Can't get user limits from ANY.RUN API: {e}")

    def submit_download(self, url: str) -> str:
        try:
            with self._connector() as connector:
                return connector.run_download_analysis(**self._submit_kwargs(url))
        except Exception as e:
            if self._is_parallel_limit_error(e):
                raise AnyRunParallelLimitError(
                    f"ANY.RUN parallel task limit reached: {e}"
                )
            raise AnyRunApiError(f"Can't submit email for analysis in ANY.RUN: {e}")

    def wait_for_verdict(self, task_id: str) -> str:
        """Block until the ANY.RUN task completes and return its verdict.

        `get_task_status` streams status events and only stops iterating once
        the task is finished, so no separate polling loop is needed here.
        """
        try:
            with self._connector() as connector:
                for status in connector.get_task_status(task_id, simplify=True):
                    logger.debug("ANY.RUN task %s status: %s", task_id, status)

                return self._get_verdict_with_retry(connector, task_id)
        except Exception as e:
            raise AnyRunApiError(f"Can't get verdict for ANY.RUN task {task_id}: {e}")

    def report_url(self, task_id: str) -> str:
        return f"{self.report_prefix}{task_id}"
