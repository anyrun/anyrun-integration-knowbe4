import logging
import os

from exceptions import ConnectorNotConfigured, NotANumber

__version__ = "1.0.0"

logger = logging.getLogger(__name__)


def _get_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or value == "":
        return default

    try:
        int_val = int(value)
    except Exception:
        raise NotANumber(f"Environment variable {name} expected to be a number")

    return int_val


def _get_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None or value == "":
        return default

    return value.strip().lower() in ("1", "true", "yes", "on")


# ---------------------------------------------------------------------------
# Proxy settings
# ---------------------------------------------------------------------------
# Proxy all outgoing requests (to PhishER and ANY.RUN) through this proxy.
# Format: http://[username:password@]host:port. Leave empty for a direct
# connection.
HTTP_PROXY_URL = os.getenv("HTTP_PROXY", "").strip()

# ---------------------------------------------------------------------------
# PhishER settings
# ---------------------------------------------------------------------------
# PhishER GraphQL API endpoint.
PHISHER_ENDPOINT = os.getenv("PHISHER_ENDPOINT", "https://knowbe4.com/graphql")
# PhishER product API token. See PhishER documentation for how to generate one.
PHISHER_API_TOKEN = os.getenv("PHISHER_API_TOKEN")
# Optional additional Lucene filter, ANDed together with the INGESTION_TAG check below.
# Empty or missing value means: no extra filtering beyond INGESTION_TAG.
PHISHER_MESSAGE_FILTER = os.getenv("PHISHER_MESSAGE_FILTER", "")
# Tag an admin applies in PhishER to opt a message into ANY.RUN scanning.
# Only messages carrying this tag are ingested. Set to "" to ingest every
# eligible (non-resolved, not already ANYRUN_*-tagged) message instead.
# Note: this tag itself is excluded from the "already has an ANYRUN_* tag"
# check (see Message._has_anyrun_tag), even though it lives in that
# namespace - it's the request to scan, not a sign of prior processing.
INGESTION_TAG = os.getenv("INGESTION_TAG", "ANYRUN_REQUEST").strip()
# If true, a malicious verdict also sets the PhishER message's `category`
# to THREAT (phisherMessageUpdate), in addition to the usual ANYRUN_* tags.
SET_CATEGORY_ON_MALICIOUS = _get_bool("SET_CATEGORY_ON_MALICIOUS", True)
# HTTP request timeout (seconds) for calls to the PhishER API.
PHISHER_REQUEST_TIMEOUT = _get_int("PHISHER_REQUEST_TIMEOUT", 30)

# ---------------------------------------------------------------------------
# ANY.RUN base settings
# ---------------------------------------------------------------------------
# ANY.RUN Sandbox API-KEY. See "Generate API token" section in the Documentation.
ANYRUN_API_KEY = os.getenv("ANYRUN_API_KEY")
# ANY.RUN root domain (used to build both the API base URL and report links).
ANYRUN_ROOT_URL = os.getenv("ANYRUN_ROOT_URL", "any.run").strip()
ANYRUN_REPORT_PREFIX = f"https://app.{ANYRUN_ROOT_URL}/tasks/"

# ---------------------------------------------------------------------------
# ANY.RUN analysis options
# ---------------------------------------------------------------------------
# Select task completion time. Size range: 10-1200 seconds.
ANYRUN_OPT_TIMEOUT = _get_int("ANYRUN_OPT_TIMEOUT", 240)
# Privacy settings. Supports: public, bylink, owner, byteam.
ANYRUN_PRIVACY_TYPE = os.getenv("ANYRUN_PRIVACY_TYPE", "bylink").strip()
if ANYRUN_PRIVACY_TYPE not in ["public", "bylink", "owner", "byteam"]:
    raise ConnectorNotConfigured(
        f"Environment variable ANYRUN_PRIVACY_TYPE was set to invalid value: {ANYRUN_PRIVACY_TYPE}"
    )
# Automated Interactivity (ML) feature, which simulates user interactions.
ANYRUN_AUTOMATED_INTERACTIVITY = _get_bool("ANYRUN_AUTOMATED_INTERACTIVITY", True)
# Enable network connection.
ANYRUN_OPT_NETWORK_CONNECT = _get_bool("ANYRUN_OPT_NETWORK_CONNECT", True)
# Enable FakeNet feature.
ANYRUN_OPT_NETWORK_FAKENET = _get_bool("ANYRUN_OPT_NETWORK_FAKENET", False)
# Enable TOR using.
ANYRUN_TOR = _get_bool("ANYRUN_TOR", False)
# TOR geolocation option. Example: US, AU.
ANYRUN_GEO = os.getenv("ANYRUN_GEO", "fastest").strip()
# Enable HTTPS MITM Proxy using.
ANYRUN_MITM = _get_bool("ANYRUN_MITM", False)
# Residential proxy using.
ANYRUN_RESIDENTIAL_PROXY = _get_bool("ANYRUN_RESIDENTIAL_PROXY", False)
# Residential proxy geolocation option. Example: US, AU.
ANYRUN_RESIDENTIAL_PROXY_GEO = os.getenv(
    "ANYRUN_RESIDENTIAL_PROXY_GEO", "fastest"
).strip()

ANYRUN_VERDICT_RETRY_ATTEMPTS = _get_int("ANYRUN_VERDICT_RETRY_ATTEMPTS", 5)
ANYRUN_VERDICT_RETRY_DELAY_SECONDS = _get_int("ANYRUN_VERDICT_RETRY_DELAY_SECONDS", 10)

# ---------------------------------------------------------------------------
# ANY.RUN analysis object settings
# ---------------------------------------------------------------------------
# Automatically change file extension to valid.
ANYRUN_OBJ_EXT_EXTENSION = _get_bool("ANYRUN_OBJ_EXT_EXTENSION", True)
# Optional command-line arguments for the analyzed object. Use an empty string
# to apply the default behavior.
ANYRUN_OBJ_EXT_CMD = os.getenv("ANYRUN_OBJ_EXT_CMD", "").strip()
# Start object from. Supported values depend on ANYRUN_OS_TYPE (see below).
ANYRUN_OBJ_EXT_STARTFOLDER = (
    os.getenv("ANYRUN_OBJ_EXT_STARTFOLDER", "temp").strip().lower()
)

# ---------------------------------------------------------------------------
# ANY.RUN analysis environment settings
# ---------------------------------------------------------------------------
# Operation system's language. Use locale identifier or country name
# (Ex: "en-US" or "Brazil"). Case-insensitive.
ANYRUN_ENV_LOCALE = os.getenv("ANYRUN_ENV_LOCALE", "en-US").strip()

# Type of OS to run the analysis in. Supports: windows, linux, macos.
# Use one set of the OS-specific settings below matching this value.
ANYRUN_OS_TYPE = os.getenv("ANYRUN_OS_TYPE", "windows").strip().lower()

_STARTFOLDER_CHOICES = {
    "windows": {"desktop", "home", "downloads", "appdata", "temp", "windows", "root"},
    "linux": {"desktop", "home", "downloads", "temp"},
    "macos": {"desktop", "home", "downloads", "temp"},
}

if ANYRUN_OS_TYPE not in _STARTFOLDER_CHOICES:
    raise ConnectorNotConfigured(
        f"Environment variable ANYRUN_OS_TYPE was set to invalid value: {ANYRUN_OS_TYPE}. "
        "Supported: windows, linux, macos"
    )

if ANYRUN_OBJ_EXT_STARTFOLDER not in _STARTFOLDER_CHOICES[ANYRUN_OS_TYPE]:
    raise ConnectorNotConfigured(
        f"Environment variable ANYRUN_OBJ_EXT_STARTFOLDER was set to invalid value "
        f"{ANYRUN_OBJ_EXT_STARTFOLDER!r} for ANYRUN_OS_TYPE={ANYRUN_OS_TYPE!r}. Supported: "
        f"{', '.join(sorted(_STARTFOLDER_CHOICES[ANYRUN_OS_TYPE]))}"
    )

# Windows analysis environment.
# Version of OS. Supports: 7, 10, 11, server 2025.
ANYRUN_ENV_VERSION = os.getenv("ANYRUN_ENV_VERSION", "10").strip().lower()
# Bitness of Operation System. Supports 32, 64.
ANYRUN_ENV_BITNESS = _get_int("ANYRUN_ENV_BITNESS", 64)
# Environment preset type. You can select "development" env for OS Windows 10
# x64. For all other cases, "complete" env is required.
ANYRUN_ENV_TYPE = os.getenv("ANYRUN_ENV_TYPE", "complete").strip().lower()
# Forces the file to execute with elevated privileges and an elevated token
# (for PE32, PE32+, PE64 files only). Windows-only.
ANYRUN_OBJ_FORCE_ELEVATION = _get_bool("ANYRUN_OBJ_FORCE_ELEVATION", False)

# Linux analysis environment.
# Run file with superuser privileges. Linux-only.
ANYRUN_RUN_AS_ROOT = _get_bool("ANYRUN_RUN_AS_ROOT", False)

# The installed anyrun-sdk version has no elevation/root kwarg on its
# download-analysis call for any OS yet, so these two settings are accepted
# (for forward-compat with future SDK versions) but currently have no effect.
if ANYRUN_OBJ_FORCE_ELEVATION or ANYRUN_RUN_AS_ROOT:
    logger.warning(
        "ANYRUN_OBJ_FORCE_ELEVATION/ANYRUN_RUN_AS_ROOT are set but not supported by the "
        "installed anyrun-sdk version's download analysis call; they will be ignored."
    )

# For Linux, the SDK only selects a distro (ubuntu/debian), not a specific
# version. ANYRUN_ENV_VERSION accepts either the distro name directly, or a
# version string like the OpenCTI connector uses (22.04.2 -> ubuntu,
# 12.2 -> debian), which gets mapped down to the distro name here.
ANYRUN_LINUX_ENV_OS: str | None = None

if ANYRUN_OS_TYPE == "windows":
    if ANYRUN_ENV_VERSION not in ("7", "10", "11", "server 2025"):
        raise ConnectorNotConfigured(
            "Environment variable ANYRUN_ENV_VERSION was set to invalid value for "
            f"Windows: {ANYRUN_ENV_VERSION}. Supported: 7, 10, 11, server 2025"
        )
    if ANYRUN_ENV_BITNESS not in (32, 64):
        raise ConnectorNotConfigured(
            "Environment variable ANYRUN_ENV_BITNESS was set to invalid value: "
            f"{ANYRUN_ENV_BITNESS}. Supported: 32, 64"
        )
    if ANYRUN_ENV_TYPE not in ("complete", "development"):
        raise ConnectorNotConfigured(
            "Environment variable ANYRUN_ENV_TYPE was set to invalid value: "
            f"{ANYRUN_ENV_TYPE}. Supported: complete, development"
        )
elif ANYRUN_OS_TYPE == "linux":
    if ANYRUN_ENV_VERSION in ("ubuntu", "debian"):
        ANYRUN_LINUX_ENV_OS = ANYRUN_ENV_VERSION
    elif ANYRUN_ENV_VERSION.startswith(("22", "24")):
        ANYRUN_LINUX_ENV_OS = "ubuntu"
    elif ANYRUN_ENV_VERSION.startswith(("11", "12")):
        ANYRUN_LINUX_ENV_OS = "debian"
    else:
        raise ConnectorNotConfigured(
            "Environment variable ANYRUN_ENV_VERSION was set to invalid value for "
            f"Linux: {ANYRUN_ENV_VERSION}. Supported: ubuntu, debian, or a version like "
            "22.04.2 (ubuntu) / 12.2 (debian)"
        )

if PHISHER_API_TOKEN is None or ANYRUN_API_KEY is None:
    raise ConnectorNotConfigured(
        "Environment variables PHISHER_API_TOKEN and ANYRUN_API_KEY should be set"
    )

# ---------------------------------------------------------------------------
# Redis settings
# ---------------------------------------------------------------------------
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = _get_int("REDIS_PORT", 6379)
REDIS_DB = _get_int("REDIS_DB", 0)

# ---------------------------------------------------------------------------
# Queue TTL settings
# ---------------------------------------------------------------------------
# How long a message (in seconds) may sit in msgs:/inprogress: before cleanup
# reports a timeout back to PhishER, and how long processed: markers are
# retained.
QUEUE_TIMEOUT_SECONDS = _get_int("QUEUE_TIMEOUT_SECONDS", 3600)
QUEUE_SAFETY_TTL_SECONDS = _get_int("QUEUE_SAFETY_TTL_SECONDS", 3600)
PROCESSED_TTL_SECONDS = _get_int("PROCESSED_TTL_SECONDS", 3600)

# ---------------------------------------------------------------------------
# Job settings
# ---------------------------------------------------------------------------
# How often each scheduled job runs, in seconds.
DISCOVERY_INTERVAL_SECONDS = _get_int("DISCOVERY_INTERVAL_SECONDS", 10)
QUEUE_INTERVAL_SECONDS = _get_int("QUEUE_INTERVAL_SECONDS", 10)
CLEANUP_INTERVAL_SECONDS = _get_int("CLEANUP_INTERVAL_SECONDS", 60)
# Max concurrently running instances of the process job (apscheduler misfire guard).
PROCESS_JOB_MAX_INSTANCES = _get_int("PROCESS_JOB_MAX_INSTANCES", 50)

# Discovery/queue page sizes.
DISCOVERY_PER_PAGE = _get_int("DISCOVERY_PER_PAGE", 200)
QUEUE_PER_PAGE = _get_int("QUEUE_PER_PAGE", 50)
MAX_DISCOVERY_PAGES = _get_int("MAX_DISCOVERY_PAGES", 3)

# ---------------------------------------------------------------------------
# Runtime/logging settings
# ---------------------------------------------------------------------------
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").strip().upper()
# Directory for rotating log files: scheduler.log (apscheduler) and app.log (everything else).
LOG_DIR = os.getenv("LOG_DIR", "logs").strip()
# Each log file rotates at this size and keeps LOG_BACKUP_COUNT old copies
# plus the active file (2 -> 3 files on disk total per log).
LOG_MAX_BYTES = _get_int("LOG_MAX_BYTES", 10 * 1024 * 1024)
LOG_BACKUP_COUNT = _get_int("LOG_BACKUP_COUNT", 2)
