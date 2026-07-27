# ANY.RUN Sandbox ↔ KnowBe4 PhishER PoC

PoC connector for submitting original PhishER `.eml` messages to ANY.RUN Sandbox **Windows** analysis via PhishER `rawUrl`, without storing the email file locally.

## Concept

This PoC intentionally avoids a local processing queue.

- PhishER tags are the queue and processing state.
- Local storage keeps only the minimal pending mapping: `phisher_message_id -> anyrun_task_id`.
- The connector is a single Python process, not a microservice architecture.

## Processing tags

Intermediate:

- `ANYRUN_QUEUED`
- `ANYRUN_PENDING`

Final success:

- `ANYRUN_SCANNED`
- one verdict tag:
  - `ANYRUN_MALICIOUS`
  - `ANYRUN_SUSPICIOUS`
  - `ANYRUN_NO_SPECIFIC_THREAT`

Final error:

- `ANYRUN_ERROR`
- `ANYRUN_TIMEOUT`

`ANYRUN_IN_PROGRESS` is only used as a legacy exclusion in the discovery query. The new flow does not add it.

## Customer-controlled filtering

The customer configures one optional PhishER query field. Empty or missing value means no customer filter:

```env
PHISHER_MESSAGE_FILTER=
PHISHER_TRIGGER_TAG_TO_REMOVE=SEND_TO_ANYRUN
```

`PHISHER_TRIGGER_TAG_TO_REMOVE` is optional. It does not select messages. It only removes the manual/customer trigger tag from the message after final writeback so the PhishER card is not cluttered. The connector checks current message tags first and removes the configured trigger tag only if it is actually present. Leave it empty if the trigger tag should remain or if the filter does not use a trigger tag.

For manual-control workflow, set `PHISHER_MESSAGE_FILTER=tags:"SEND_TO_ANYRUN"`. If the filter field is set, the connector combines it with internal ANY.RUN exclusions:

```text
(<ANYRUN exclusions>) AND (<customer filter>)
```

If the field is empty or not defined, the connector processes all eligible non-resolved PhishER messages that do not already have ANYRUN processing/result tags. Internal exclusions are always added automatically, including ANYRUN state/result tags and `-status:"Resolved"`. In this mode `PHISHER_TRIGGER_TAG_TO_REMOVE=SEND_TO_ANYRUN` is safe: the connector will not try to delete `SEND_TO_ANYRUN` from messages where that tag is absent.

## Runtime flow

```text
Customer filter / empty filter
        ↓
Discovery polling
        ↓
pipelineStatus == PROCESSED
        ↓
add ANYRUN_QUEUED
        ↓
Submit worker finds ANYRUN_QUEUED
        ↓
submit rawUrl directly to ANY.RUN Windows Sandbox
        ↓
ANY.RUN downloads the original email from PhishER rawUrl using download analysis
        ↓
ANYRUN_QUEUED → ANYRUN_PENDING
        ↓
save phisher_message_id → anyrun_task_id
        ↓
Pending watcher checks ANY.RUN task
        ↓
task completed
        ↓
ANYRUN_PENDING → ANYRUN_SCANNED + verdict tag
        ↓
add comment with report URL
        ↓
delete pending mapping
```

## Windows Sandbox

The PoC uses:

```python
SandboxConnector.windows(api_key)
```

and submits with download analysis:

```python
connector.run_download_analysis(obj_url=raw_url, env_version="10", opt_privacy_hidesource=True)
```

The connector does not download or store `.eml` files locally. It passes PhishER `rawUrl` directly to ANY.RUN using SDK `run_download_analysis()` (`obj_type=download`), and ANY.RUN retrieves the original email from that URL.



## Docker deployment

The connector can run as a single Docker container. It does not expose inbound ports; it only needs outbound access to:

- KnowBe4 PhishER GraphQL endpoint
- ANY.RUN API

SQLite is still used only for the minimal pending mapping `phisher_message_id -> anyrun_task_id`. In Docker it is stored in a persistent volume at `/data/pending_tasks.sqlite`.

### Build image

```bash
docker build -t anyrun-phisher-connector:latest .
```

### Run with Docker

```bash
cp .env.docker.example .env
# edit .env and set PHISHER_API_TOKEN and ANYRUN_API_KEY
docker run --rm \
  --env-file .env \
  -v anyrun-phisher-data:/data \
  -e PENDING_DB_PATH=/data/pending_tasks.sqlite \
  anyrun-phisher-connector:latest
```

### Run with Docker Compose

```bash
cp .env.docker.example .env
# edit .env and set PHISHER_API_TOKEN and ANYRUN_API_KEY
docker compose up -d --build
docker compose logs -f
```

After changing `.env`, recreate the container so Docker Compose applies the new environment:

```bash
docker compose up -d --build --force-recreate
```

To stop:

```bash
docker compose down
```

To remove the pending SQLite volume:

```bash
docker compose down -v
```

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

On Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
```

Edit `.env`:

```env
PHISHER_ENDPOINT=https://ca.knowbe4.com/graphql
PHISHER_API_TOKEN=...
ANYRUN_API_KEY=...
ANYRUN_WINDOWS_ENV_VERSION=10
PHISHER_MESSAGE_FILTER=
PHISHER_TRIGGER_TAG_TO_REMOVE=SEND_TO_ANYRUN
```

Run:

```bash
python run.py
```

## Important PoC notes

1. `rawUrl` is refreshed before every submit attempt via `phisherMessage(id)`.
2. The connector does not store original `.eml` files in `tmp` or any local directory.
3. If `pipelineStatus != PROCESSED`, the message is skipped and will be checked again on the next discovery polling cycle.
4. If ANY.RUN returns a parallel task limit error, the connector leaves `ANYRUN_QUEUED` on the message and retries later.
5. The connector writes a short PhishER comment only:

```text
ANY.RUN result: MALICIOUS ACTIVITY. Malicious activity detected in sandbox. Full report: https://app.any.run/tasks/<task_id>
```

6. The PoC does not post full HTML reports or large IOC lists into PhishER Discussion.
7. Completed jobs are not retained locally. Only active pending task mappings are stored.

## Minimal local storage

SQLite table:

```sql
CREATE TABLE pending_tasks (
    phisher_message_id TEXT PRIMARY KEY,
    anyrun_task_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
```

This is not a queue. It exists only so the connector can recover after restart and continue checking ANY.RUN tasks that were already submitted.

## Queue ordering note

The submit worker requests queued messages with `sortField: REPORTED_AT` and `sortDirection: ASCENDING`, then additionally sorts the returned page client-side by the `CREATED.createdAt` event before submitting. This makes FIFO behavior deterministic within the fetched queue page.

### Resolved message handling

Resolved PhishER messages are excluded in two layers:

- discovery query includes `-status:"Resolved"`;
- connector also checks GraphQL `actionStatus == RESOLVED` before queueing/submitting.

If a message was already tagged `ANYRUN_QUEUED` and then becomes Resolved before submission, the connector removes `ANYRUN_QUEUED` and does not submit it to ANY.RUN.
