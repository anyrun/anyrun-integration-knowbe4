import logging

from apscheduler.schedulers.blocking import BlockingScheduler

from connector import Connector
from const import (
    CLEANUP_INTERVAL_SECONDS,
    DISCOVERY_INTERVAL_SECONDS,
    LOG_BACKUP_COUNT,
    LOG_DIR,
    LOG_LEVEL,
    LOG_MAX_BYTES,
    PROCESS_JOB_MAX_INSTANCES,
    QUEUE_INTERVAL_SECONDS,
)
from logging_setup import configure_logging

logger = logging.getLogger(__name__)


def main() -> None:
    configure_logging(
        LOG_LEVEL,
        log_dir=LOG_DIR,
        max_bytes=LOG_MAX_BYTES,
        backup_count=LOG_BACKUP_COUNT,
    )

    connector = Connector()
    scheduler = BlockingScheduler()

    # ingest and cleanup are strictly one-task-per-instance: a new run never
    # starts while a previous one is still going.
    scheduler.add_job(
        connector.ingest,
        trigger="interval",
        seconds=DISCOVERY_INTERVAL_SECONDS,
        id="ingest",
        max_instances=1,
        coalesce=True,
    )
    scheduler.add_job(
        connector.cleanup,
        trigger="interval",
        seconds=CLEANUP_INTERVAL_SECONDS,
        id="cleanup",
        max_instances=1,
        coalesce=True,
    )

    # process has no meaningful max_instances cap: every run checks available
    # ANY.RUN slots itself and skips immediately if none are free, so
    # overlapping runs are fine by design - a run blocked waiting on one
    # sandbox result doesn't stop later ticks from picking up other queued
    # messages. Queue.claim_message() does the actual dequeue atomically so
    # two overlapping runs can never submit the same message twice.
    scheduler.add_job(
        connector.process,
        trigger="interval",
        seconds=QUEUE_INTERVAL_SECONDS,
        id="process",
        max_instances=PROCESS_JOB_MAX_INSTANCES,
    )

    logger.info("Starting ANY.RUN <-> PhishER connector")

    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()


if __name__ == "__main__":
    main()
