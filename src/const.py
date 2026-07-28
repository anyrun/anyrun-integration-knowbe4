import os

from exceptions import ConnectorNotConfigured, NotANumber

__version__ = "1.0.0"


def _get_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or value == "":
        return default

    try:
        int_val = int(value)
    except Exception:
        raise NotANumber(f"Environment variable {name} expected to be a number")

    return int_val


# PhishER
PHISHER_ENDPOINT = os.getenv("PHISHER_ENDPOINT", "https://knowbe4.com/graphql")
PHISHER_API_TOKEN = os.getenv("PHISHER_API_TOKEN")
PHISHER_MESSAGE_FILTER = os.getenv("PHISHER_MESSAGE_FILTER", "")
# Tag an admin applies in PhishER to opt a message into ANY.RUN scanning.
# Only messages carrying this tag are ingested. Set to "" to ingest every
# eligible (non-resolved, not already ANYRUN_*-tagged) message instead.
# Note: this tag itself is excluded from the "already has an ANYRUN_* tag"
# check (see Message._has_anyrun_tag), even though it lives in that
# namespace - it's the request to scan, not a sign of prior processing.
INGESTION_TAG = os.getenv("INGESTION_TAG", "ANYRUN_REQUEST").strip()
PHISHER_REQUEST_TIMEOUT = _get_int("PHISHER_REQUEST_TIMEOUT", 30)

# ANY.RUN
ANYRUN_API_KEY = os.getenv("ANYRUN_API_KEY")
ANYRUN_WINDOWS_ENV_VERSION = os.getenv("ANYRUN_WINDOWS_ENV_VERSION", "10")
ANYRUN_PRIVACY_TYPE = os.getenv("ANYRUN_PRIVACY_TYPE", "bylink")
ANYRUN_ANALYSIS_DURATION = _get_int("ANYRUN_ANALYSIS_DURATION", 240)
ANYRUN_ROOT_URL = os.getenv("ANYRUN_ROOT_URL", "any.run")
ANYRUN_REPORT_PREFIX = f"https://app.{ANYRUN_ROOT_URL}/tasks/"

if ANYRUN_PRIVACY_TYPE not in ["public", "bylink", "owner", "byteam"]:
    raise ConnectorNotConfigured(
        f"Environment variable ANYRUN_PRIVACY_TYPE was set to invalid value: {ANYRUN_PRIVACY_TYPE}"
    )

ANYRUN_VERDICT_RETRY_ATTEMPTS = _get_int("ANYRUN_VERDICT_RETRY_ATTEMPTS", 5)
ANYRUN_VERDICT_RETRY_DELAY_SECONDS = _get_int("ANYRUN_VERDICT_RETRY_DELAY_SECONDS", 10)

if PHISHER_API_TOKEN is None or ANYRUN_API_KEY is None:
    raise ConnectorNotConfigured(
        "Environment variables PHISHER_API_TOKEN and ANYRUN_API_KEY should be set"
    )

# Redis connection
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = _get_int("REDIS_PORT", 6379)
REDIS_DB = _get_int("REDIS_DB", 0)

# Queue TTLs
QUEUE_TIMEOUT_SECONDS = _get_int("QUEUE_TIMEOUT_SECONDS", 3600)
QUEUE_SAFETY_TTL_SECONDS = _get_int("QUEUE_SAFETY_TTL_SECONDS", 3600)
PROCESSED_TTL_SECONDS = _get_int("PROCESSED_TTL_SECONDS", 3600)

# Job intervals
DISCOVERY_INTERVAL_SECONDS = _get_int("DISCOVERY_INTERVAL_SECONDS", 10)
QUEUE_INTERVAL_SECONDS = _get_int("QUEUE_INTERVAL_SECONDS", 10)
CLEANUP_INTERVAL_SECONDS = _get_int("CLEANUP_INTERVAL_SECONDS", 60)

DISCOVERY_PER_PAGE = _get_int("DISCOVERY_PER_PAGE", 200)
QUEUE_PER_PAGE = _get_int("QUEUE_PER_PAGE", 50)
MAX_DISCOVERY_PAGES = _get_int("MAX_DISCOVERY_PAGES", 3)

PROCESS_JOB_MAX_INSTANCES = _get_int("PROCESS_JOB_MAX_INSTANCES", 50)

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").strip().upper()
LOG_DIR = os.getenv("LOG_DIR", "logs").strip()
LOG_MAX_BYTES = _get_int("LOG_MAX_BYTES", 10 * 1024 * 1024)
LOG_BACKUP_COUNT = _get_int("LOG_BACKUP_COUNT", 2)
