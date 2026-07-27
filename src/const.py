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
INGESTION_TAG = os.getenv("INGESTION_TAG", "SEND_TO_ANYRUN").strip()
PHISHER_REQUEST_TIMEOUT = _get_int("PHISHER_REQUEST_TIMEOUT", 30)

# ANY.RUN
ANYRUN_API_KEY = os.getenv("ANYRUN_API_KEY")
ANYRUN_WINDOWS_ENV_VERSION = os.getenv("ANYRUN_WINDOWS_ENV_VERSION", "10")
ANYRUN_ROOT_URL = os.getenv("ANYRUN_ROOT_URL", "any.run")
ANYRUN_REPORT_PREFIX = f"https://app.{ANYRUN_ROOT_URL}/tasks/"

# The task-status stream can report a task as finished slightly before the
# report's verdict/scores are actually populated server-side. Retry fetching
# the verdict a few times before giving up.
ANYRUN_VERDICT_RETRY_ATTEMPTS = _get_int("ANYRUN_VERDICT_RETRY_ATTEMPTS", 5)
ANYRUN_VERDICT_RETRY_DELAY_SECONDS = _get_int("ANYRUN_VERDICT_RETRY_DELAY_SECONDS", 10)

if PHISHER_API_TOKEN is None or ANYRUN_API_KEY is None:
    raise ConnectorNotConfigured(
        "Environment variables PHISHER_API_TOKEN and ANYRUN_API_KEY should be set"
    )

# Redis
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = _get_int("REDIS_PORT", 6379)
REDIS_DB = _get_int("REDIS_DB", 0)

# Queue timing
# How long a message may wait in `msgs:`/`inprogress:` before the cleanup job
# considers it stuck and reports a timeout back to PhishER.
QUEUE_TIMEOUT_SECONDS = _get_int("QUEUE_TIMEOUT_SECONDS", 3600)
# Safety-net TTL applied to `msgs:`/`inprogress:` Redis keys so a dead cleanup
# job can't leak them forever. Should stay well above QUEUE_TIMEOUT_SECONDS.
QUEUE_SAFETY_TTL_SECONDS = _get_int("QUEUE_SAFETY_TTL_SECONDS", 3600)
# How long finished `processed:` markers are kept around for observability.
PROCESSED_TTL_SECONDS = _get_int("PROCESSED_TTL_SECONDS", 3600)

# Job intervals
DISCOVERY_INTERVAL_SECONDS = _get_int("DISCOVERY_INTERVAL_SECONDS", 10)
QUEUE_INTERVAL_SECONDS = _get_int("QUEUE_INTERVAL_SECONDS", 10)
CLEANUP_INTERVAL_SECONDS = _get_int("CLEANUP_INTERVAL_SECONDS", 60)

DISCOVERY_PER_PAGE = _get_int("DISCOVERY_PER_PAGE", 200)
QUEUE_PER_PAGE = _get_int("QUEUE_PER_PAGE", 50)
MAX_DISCOVERY_PAGES = _get_int("MAX_DISCOVERY_PAGES", 3)

# The process job has no max_instances cap: each run checks available ANY.RUN
# slots itself and skips if none are free, so apscheduler is allowed to fire
# overlapping runs of it (e.g. while one run is still blocked waiting on a
# sandbox result, later ticks can start and pick up other queued messages).
# APScheduler's own default max_instances is 1, so this must be set explicitly
# high enough that it never becomes the actual bottleneck.
PROCESS_JOB_MAX_INSTANCES = _get_int("PROCESS_JOB_MAX_INSTANCES", 50)

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").strip().upper()
LOG_DIR = os.getenv("LOG_DIR", "logs").strip()
LOG_MAX_BYTES = _get_int("LOG_MAX_BYTES", 10 * 1024 * 1024)
# Rotated log files kept per log, in addition to the currently-active one.
# 2 backups + the active file = 3 files on disk total.
LOG_BACKUP_COUNT = _get_int("LOG_BACKUP_COUNT", 2)
