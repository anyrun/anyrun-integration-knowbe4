import logging
import time

from anyrun.connectors import SandboxConnector
from pydantic import BaseModel

from const import (
    ANYRUN_API_KEY,
    ANYRUN_REPORT_PREFIX,
    ANYRUN_ROOT_URL,
    ANYRUN_VERDICT_RETRY_ATTEMPTS,
    ANYRUN_VERDICT_RETRY_DELAY_SECONDS,
    ANYRUN_WINDOWS_ENV_VERSION,
    __version__,
)
from exceptions import AnyRunApiError, AnyRunParallelLimitError

logger = logging.getLogger(__name__)


class UserLimits(BaseModel):
    total: int
    available: int


class ANYRUN:
    def __init__(self) -> None:
        self.api_key = ANYRUN_API_KEY
        self.windows_env_version = ANYRUN_WINDOWS_ENV_VERSION
        self.root_url = ANYRUN_ROOT_URL
        self.report_prefix = ANYRUN_REPORT_PREFIX

        self.telemetry = f"KnowBe4PhishER:{__version__}"

    def _connector(self) -> SandboxConnector:
        # A fresh connector is created per call (instead of reusing one shared
        # instance) so concurrent worker threads never share SDK connection state.
        return SandboxConnector.windows(
            api_key=self.api_key,
            integration=self.telemetry,
            root_url=self.root_url,
        )

    @staticmethod
    def _is_parallel_limit_error(error: Exception) -> bool:
        text = str(error).lower()
        return "parallel" in text and (
            "limit" in text or "maximum" in text or "quota" in text
        )

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

    def submit_download_windows(self, url: str) -> str:
        try:
            with self._connector() as connector:
                return connector.run_download_analysis(
                    obj_url=url,
                    env_version=self.windows_env_version,
                    opt_privacy_hidesource=True,
                    opt_timeout=240,
                )
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
                    "Verdict not available yet for ANY.RUN task %s "
                    "(attempt %s/%s): %s",
                    task_id,
                    attempt,
                    ANYRUN_VERDICT_RETRY_ATTEMPTS,
                    e,
                )
                if attempt < ANYRUN_VERDICT_RETRY_ATTEMPTS:
                    time.sleep(ANYRUN_VERDICT_RETRY_DELAY_SECONDS)

        raise last_error

    def report_url(self, task_id: str) -> str:
        return f"{self.report_prefix}{task_id}"
