# ANY.RUN Sandbox ↔ KnowBe4 PhishER connector

Please refer to API Documentation for setting up this connector: https://any.run/api-documentation/#description/introduction

Submits PhishER-reported emails to ANY.RUN Sandbox for analysis and writes the
verdict back to PhishER as tags + a comment, without storing the original
`.eml` file locally. Runs as three scheduled jobs backed by Redis for local
queue state.

`anyrun_phisher_connector/` is an earlier prototype kept only for reference.
The real implementation lives in [`src/`](src/).

## Architecture

Three [APScheduler](https://apscheduler.readthedocs.io/) interval jobs, wired
up in [`src/main.py`](src/main.py), coordinate over a small Redis-backed
queue in [`src/redis_queue.py`](src/redis_queue.py):

```text
PhishER                         Redis                         ANY.RUN
--------                        -----                         -------
job 1 "ingest"
  query eligible messages
  tag ANYRUN_QUEUED     ------> msgs:<id>

job 2 "process"                msgs:<id> --(atomic claim)--> inprogress:<id>
  claim message                                    |
  tag ANYRUN_PENDING                                v
  submit rawUrl                              submit_download_windows()
                                                     |
                                                     v
  wait for verdict     <----------------------  wait_for_verdict()
  tag ANYRUN_SCANNED
    + verdict tag
  write comment
  finish            inprogress:<id> --> processed:<id>

job 3 "cleanup"
  timeout stuck msgs:/inprogress: entries -> tag ANYRUN_TIMEOUT
  re-enqueue ANYRUN_QUEUED/PENDING tags with no matching Redis entry
```

### Job 1 — ingest (`Connector.ingest`)

Runs on `DISCOVERY_INTERVAL_SECONDS`. Queries PhishER for messages matching
`INGESTION_TAG` (plus the optional `PHISHER_MESSAGE_FILTER`) that:

- have `pipelineStatus == PROCESSED`
- are not `RESOLVED`
- don't already carry any `ANYRUN_*` tag

Each match is written to Redis as `msgs:<message_id>` and tagged
`ANYRUN_QUEUED`. If the message is already tracked anywhere in Redis
(`msgs:`/`inprogress:`), it's skipped — except a stale `processed:` marker
from a *previous* run does **not** block re-ingestion, so re-applying
`INGESTION_TAG` to an already-scanned message triggers a fresh analysis.

### Job 2 — process (`Connector.process`)

Runs on `QUEUE_INTERVAL_SECONDS`. Unlike jobs 1 and 3, this job has **no**
one-at-a-time lock (`max_instances` is set to `PROCESS_JOB_MAX_INSTANCES`,
not 1): a run blocked for minutes waiting on a sandbox result doesn't stop
later ticks from picking up other queued messages. Each run:

1. Reads all `msgs:*` entries, oldest PhishER-reported email first
   (`Queue.fetch_with_order`, sorted by a `created_at` Redis hash populated
   at enqueue time from each message's `CREATED` event — not by local
   enqueue time, so processing order matches original report order even if
   messages were discovered out of order or requeued after an error).
2. For each one, atomically claims it (Redis `GETDEL` — only one caller ever
   wins if two overlapping runs see the same message).
3. Tags `ANYRUN_PENDING` (and drops `ANYRUN_QUEUED` + `INGESTION_TAG`) and
   submits the PhishER `rawUrl` directly to ANY.RUN as a Windows download
   analysis — the email itself is never downloaded or stored locally.
4. Blocks until the ANY.RUN task finishes, then fetches the verdict (retried
   `ANYRUN_VERDICT_RETRY_ATTEMPTS` times — the task-status stream can report
   "done" slightly before the verdict is actually written server-side).
5. Tags `ANYRUN_SCANNED` + a verdict tag, writes a comment with the report
   URL, and moves the message to `processed:`.
6. If the verdict is `malicious` and `SET_CATEGORY_ON_MALICIOUS` is enabled
   (default), also sets the PhishER message's `category` to `THREAT` via
   `phisherMessageUpdate`. This is best-effort: a failure here is logged but
   does not undo the tags/comment already written or block finishing the
   message.

If ANY.RUN reports no available parallel slot mid-submit, the message is
returned to `msgs:` (re-tagged `ANYRUN_QUEUED`) instead of erroring. Any other
failure tags `ANYRUN_ERROR` with the error in a comment.

### Job 3 — cleanup (`Connector.cleanup`)

Runs on `CLEANUP_INTERVAL_SECONDS`. Two independent checks:

- **Stuck queue entries**: anything sitting in `msgs:`/`inprogress:` longer
  than `QUEUE_TIMEOUT_SECONDS` is dropped and the message is tagged
  `ANYRUN_TIMEOUT`.
- **Orphaned tags**: messages tagged `ANYRUN_QUEUED`/`ANYRUN_PENDING` in
  PhishER but with no matching Redis entry (e.g. after a Redis restart) are
  re-enqueued into `msgs:` so processing resumes.

## Tags

| Tag | Meaning |
|---|---|
| `ANYRUN_REQUEST` (`INGESTION_TAG`) | Applied by an admin to opt a message into scanning |
| `ANYRUN_QUEUED` | Enqueued in `msgs:`, waiting for job 2 |
| `ANYRUN_PENDING` | Claimed by job 2, submitted to ANY.RUN, awaiting verdict |
| `ANYRUN_SCANNED` | Analysis finished successfully (paired with a verdict tag below) |
| `ANYRUN_MALICIOUS` / `ANYRUN_SUSPICIOUS` / `ANYRUN_NO_SPECIFIC_THREAT` | Verdict |
| `ANYRUN_ERROR` | Submission or verdict retrieval failed |
| `ANYRUN_TIMEOUT` | Stuck too long in a local queue (job 3) or ANY.RUN task timed out |

Any message already carrying an `ANYRUN_*` tag is excluded from discovery, so
`ANYRUN_SCANNED` effectively marks "already processed." `ANYRUN_REQUEST`
itself lives in the same `ANYRUN_*` namespace but is specifically excluded
from that check (`Message._has_anyrun_tag`) — it's the request to scan, not
a sign of prior/ongoing processing, so it must not block its own ingestion.

## Configuration

All configuration is environment variables, loaded from `.env` (see
[`.env.example`](.env.example) for the full list with defaults/comments).
Required: `PHISHER_API_TOKEN`, `ANYRUN_API_KEY`.

| Variable | Default | Purpose |
|---|---|---|
| `PHISHER_ENDPOINT` | `https://ca.knowbe4.com/graphql` | PhishER GraphQL endpoint |
| `PHISHER_API_TOKEN` | *(required)* | PhishER product API token |
| `INGESTION_TAG` | `ANYRUN_REQUEST` | Tag required for a message to be ingested; empty = ingest everything eligible |
| `PHISHER_MESSAGE_FILTER` | *(empty)* | Extra Lucene filter ANDed with `INGESTION_TAG` |
| `SET_CATEGORY_ON_MALICIOUS` | `true` | Also set the PhishER message `category` to `THREAT` on a malicious verdict |
| `ANYRUN_API_KEY` | *(required)* | ANY.RUN API key |
| `ANYRUN_WINDOWS_ENV_VERSION` | `10` | Windows Sandbox version for download analysis |
| `ANYRUN_PRIVACY_TYPE` | `bylink` | ANY.RUN analysis privacy (`public`/`bylink`/`owner`/`byteam`) |
| `ANYRUN_ANALYSIS_DURATION` | `240` | Sandbox analysis timeout in seconds |
| `ANYRUN_ROOT_URL` | `any.run` | ANY.RUN root URL (also used to build report links) |
| `ANYRUN_VERDICT_RETRY_ATTEMPTS` | `5` | Verdict-fetch retry attempts before tagging `ANYRUN_ERROR` |
| `ANYRUN_VERDICT_RETRY_DELAY_SECONDS` | `10` | Delay between verdict-fetch retries |
| `REDIS_HOST` / `REDIS_PORT` / `REDIS_DB` | `redis` / `6379` / `0` | Redis connection |
| `DISCOVERY_INTERVAL_SECONDS` | `300` | Job 1 interval |
| `QUEUE_INTERVAL_SECONDS` | `30` | Job 2 interval |
| `CLEANUP_INTERVAL_SECONDS` | `300` | Job 3 interval |
| `PROCESS_JOB_MAX_INSTANCES` | `50` | Cap on overlapping job 2 runs |
| `QUEUE_TIMEOUT_SECONDS` | `3600` | Age before job 3 times out a stuck `msgs:`/`inprogress:` entry |
| `QUEUE_SAFETY_TTL_SECONDS` | `3600` | Redis TTL backstop on `msgs:`/`inprogress:` keys |
| `PROCESSED_TTL_SECONDS` | `3600` | Redis TTL on `processed:` markers |
| `DISCOVERY_PER_PAGE` / `QUEUE_PER_PAGE` / `MAX_DISCOVERY_PAGES` | `200` / `50` / `3` | PhishER pagination |
| `LOG_LEVEL` | `INFO` | Root log level |
| `LOG_DIR` | `logs` | Directory for rotating log files |
| `LOG_MAX_BYTES` / `LOG_BACKUP_COUNT` | `10485760` / `2` | Log rotation size and backup count (2 backups + active file = 3 files on disk per log) |

## Logging

Console output is colored by subsystem: `apscheduler` (green), `anyrun_connector`
(blue), `phisher` (orange). Everything is also written to rotating files under
`LOG_DIR`:

- `scheduler.log` — everything from the `apscheduler` logger tree
- `app.log` — everything else (phisher, anyrun_connector, connector, main)

Each file rotates at `LOG_MAX_BYTES` and keeps `LOG_BACKUP_COUNT` old copies
plus the active file. See [`src/logging_setup.py`](src/logging_setup.py).

## Running locally

```bash
uv sync                 # installs runtime deps (see Testing below for dev deps)
cp .env.example .env    # fill in PHISHER_API_TOKEN and ANYRUN_API_KEY
```

You need a reachable Redis (`docker run -p 6379:6379 redis:8` works for local
dev) and `REDIS_HOST=localhost` in `.env`.

`src/*.py` use flat imports (`from const import ...`, not
`from src.const import ...`). Run it as a script from the repo root — Python
automatically adds a script's own directory to `sys.path`, so this satisfies
the flat imports without needing `cd src` first. That matters: `LOG_DIR`
(default `logs`) is resolved relative to the current working directory, so
running from the repo root is also what puts log files in `./logs` instead of
`./src/logs`.

```bash
uv run --env-file .env python src/main.py
```

## Docker

`docker-compose.yml` runs two services: `app` (this connector) and `redis:8`
with an `appendonly` data volume. The Dockerfile copies `src/` flattened
directly into `/app` (so the same flat-import style works unmodified) and
runs as a non-root `connector` user.

```bash
docker compose up -d --build
docker compose logs -f app
```

Log files land in `./logs` on the host via a bind mount (not a named Docker
volume), so `logs/scheduler.log` / `logs/app.log` are just regular files in
the project directory.

## Testing

```bash
uv run pytest
```

Tests live in [`tests/`](tests/) and mock everything external — Redis via
[`fakeredis`](https://github.com/cunla/fakeredis-py), PhishER's
`requests.Session`, and ANY.RUN's `SandboxConnector` — so the suite needs no
live server, PhishER account, or ANY.RUN account.

Test/dev-only dependencies (`pytest`, `pytest-cov`, `fakeredis`) live under
`[dependency-groups] dev` in `pyproject.toml` (PEP 735), not
`[project.dependencies]`. The Dockerfile's `pip install .` only ever
resolves `[project.dependencies]`, so none of this leaks into the image.

Coverage report:

```bash
uv run pytest --cov --cov-report=term-missing
# or, for an interactive line-by-line HTML report:
uv run pytest --cov --cov-report=html   # see htmlcov/index.html
```
