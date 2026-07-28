import logging

from anyrun_connector import ANYRUN
from const import (
    INGESTION_TAG,
    MAX_DISCOVERY_PAGES,
    QUEUE_PER_PAGE,
    QUEUE_TIMEOUT_SECONDS,
    SET_CATEGORY_ON_MALICIOUS,
)
from exceptions import AnyRunParallelLimitError
from message import Message
from phisher import Phisher
from redis_queue import Queue
from tags import Tags

logger = logging.getLogger(__name__)


class Connector:
    def __init__(self) -> None:
        self.anyrun = ANYRUN()
        self.queue = Queue()

    def _enqueue(self, phisher: Phisher, message: Message) -> None:
        if message.pipeline_status != "PROCESSED":
            logger.debug(
                "Skipping %s: pipelineStatus=%s",
                message.message_id,
                message.pipeline_status,
            )
            return
        if message.action_status == "RESOLVED":
            logger.debug("Skipping %s: actionStatus=RESOLVED", message.message_id)
            return
        if message.has_anyrun_tag:
            logger.debug("Skipping %s: already has ANYRUN_* tag", message.message_id)
            return

        enqueued, reason = self.queue.enqueue_message(message)
        if not enqueued:
            logger.debug("Not enqueuing %s: %s", message.message_id, reason)
            return

        try:
            logger.info(
                "Enqueued %s, tagging as %s", message.message_id, Tags.anyrun_queued
            )
            phisher.add_tags(message, [Tags.anyrun_queued])
        except Exception:
            logger.exception("Failed to tag %s as queued", message.message_id)

    def _process_one(self, message_id: str) -> None:
        with Phisher() as phisher:
            try:
                message = phisher.get_message(message_id)
            except Exception:
                logger.exception(
                    "Can't refresh message %s before processing; leaving queued",
                    message_id,
                )
                return

            if message.action_status == "RESOLVED":
                logger.info(
                    "Message %s is RESOLVED; removing from queue without submitting",
                    message_id,
                )
                self.queue.drop_message(message_id)
                self._safe_remove_tags(phisher, message, [Tags.anyrun_queued])
                return

            if not self.queue.claim_message(message_id):
                logger.debug(
                    "Message %s already claimed by another overlapping run; skipping",
                    message_id,
                )
                return

            try:
                tags_to_drop = [Tags.anyrun_queued]
                if INGESTION_TAG:
                    tags_to_drop.append(INGESTION_TAG)
                self._safe_remove_tags(phisher, message, tags_to_drop)
                phisher.add_tags(message, [Tags.anyrun_pending])

                logger.info("Submitting %s to ANY.RUN", message_id)
                task_id = self.anyrun.submit_download_windows(message.raw_url)

                logger.info(
                    "Waiting for ANY.RUN task %s (message %s)", task_id, message_id
                )
                verdict = self.anyrun.wait_for_verdict(task_id)
                verdict_tag = Tags.map_verdict_to_tag(verdict)
                report_url = self.anyrun.report_url(task_id)

                phisher.remove_tags(message, [Tags.anyrun_pending])
                phisher.add_tags(message, [Tags.anyrun_scanned, verdict_tag])
                phisher.add_comment(
                    message,
                    f"ANY.RUN result: {verdict.upper()}. Link to analysis: {report_url}",
                )

                if verdict_tag == Tags.anyrun_malicious and SET_CATEGORY_ON_MALICIOUS:
                    self._safe_set_category(phisher, message, Tags.category_threat)

                self.queue.finish_processing(message_id)
                logger.info("Finished processing %s: %s", message_id, verdict)

            except AnyRunParallelLimitError:
                logger.info(
                    "ANY.RUN parallel limit hit mid-submit for %s; returning to queue",
                    message_id,
                )
                self._requeue(phisher, message)
            except Exception as error:
                logger.exception("Processing failed for %s", message_id)
                self.queue.drop_message(message_id)
                self._write_error(phisher, message, error)

    def _requeue(self, phisher: Phisher, message: Message) -> None:
        self.queue.drop_message(message.message_id)
        try:
            self._safe_remove_tags(phisher, message, [Tags.anyrun_pending])
            enqueued, reason = self.queue.enqueue_message(message)
            if enqueued:
                phisher.add_tags(message, [Tags.anyrun_queued])
            else:
                logger.warning("Could not requeue %s: %s", message.message_id, reason)
        except Exception:
            logger.exception("Failed to requeue %s", message.message_id)

    def _write_error(
        self, phisher: Phisher, message: Message, error: Exception
    ) -> None:
        try:
            self._safe_remove_tags(
                phisher, message, [Tags.anyrun_queued, Tags.anyrun_pending]
            )
            phisher.add_tags(message, [Tags.anyrun_error])
            phisher.add_comment(message, f"ANY.RUN result: ERROR. {error}")
        except Exception:
            logger.exception(
                "Failed to write error state to PhishER for %s", message.message_id
            )

    def _safe_remove_tags(
        self, phisher: Phisher, message: Message, tags: list[str]
    ) -> None:
        try:
            phisher.remove_tags(message, tags)
        except Exception:
            logger.exception(
                "Failed to remove tags %s from %s", tags, message.message_id
            )

    def _safe_set_category(
        self, phisher: Phisher, message: Message, category: str
    ) -> None:
        try:
            phisher.set_category(message, category)
        except Exception:
            logger.exception(
                "Failed to set category %s on %s", category, message.message_id
            )

    def _cleanup_stale_queue(self, prefix: str, tags_to_remove: list[str]) -> None:
        stale_ids = self.queue.get_stale_messages(prefix, QUEUE_TIMEOUT_SECONDS)
        if not stale_ids:
            return

        with Phisher() as phisher:
            for message_id in stale_ids:
                logger.warning(
                    "Message %s stuck in %s queue for too long; cleaning up",
                    message_id,
                    prefix,
                )
                self.queue.drop_message(message_id)
                try:
                    message = phisher.get_message(message_id)
                    self._safe_remove_tags(phisher, message, tags_to_remove)
                    phisher.add_tags(message, [Tags.anyrun_timeout])
                    phisher.add_comment(
                        message,
                        "ANY.RUN result: TIMEOUT. Message waited too long in "
                        "internal processing queue.",
                    )
                except Exception:
                    logger.exception("Failed to write timeout state for %s", message_id)

    def _reconcile_orphaned_tags(self) -> None:
        with Phisher() as phisher:
            for tag in (Tags.anyrun_queued, Tags.anyrun_pending):
                try:
                    messages, _pagination = phisher.list_messages(
                        page=1,
                        query=Tags.tag_query(tag),
                        per=QUEUE_PER_PAGE,
                    )
                except Exception:
                    logger.exception("Failed to query messages tagged %s", tag)
                    continue

                for message in messages:
                    if self.queue.is_queued(message.message_id):
                        continue

                    logger.warning(
                        "Message %s tagged %s but missing from local queues; "
                        "re-enqueuing",
                        message.message_id,
                        tag,
                    )
                    try:
                        self._safe_remove_tags(phisher, message, [tag])
                        enqueued, reason = self.queue.enqueue_message(message)
                        if enqueued:
                            phisher.add_tags(message, [Tags.anyrun_queued])
                        else:
                            logger.debug(
                                "Could not re-enqueue %s: %s",
                                message.message_id,
                                reason,
                            )
                    except Exception:
                        logger.exception(
                            "Failed to reconcile orphaned tag for %s",
                            message.message_id,
                        )

    # ------------------------------------------------------------------
    # Job 1: discover eligible PhishER messages and enqueue them locally
    # ------------------------------------------------------------------
    def ingest(self) -> None:
        with Phisher() as phisher:
            for page in range(1, MAX_DISCOVERY_PAGES + 1):
                try:
                    messages, pagination = phisher.list_messages(page=page)
                except Exception:
                    logger.exception("Discovery failed on page %s", page)
                    return

                if not messages:
                    return

                for message in messages:
                    self._enqueue(phisher, message)

                if page >= int(pagination.get("pages", 1)):
                    return

    # ------------------------------------------------------------------
    # Job 2: check the account's available parallel task slots; if none are
    # free, skip this run entirely. Otherwise submit queued messages one at a
    # time (no internal concurrency - apscheduler runs one task per instance)
    # ------------------------------------------------------------------
    def process(self) -> None:
        try:
            limits = self.anyrun.get_parallel_limits()
        except Exception:
            logger.exception("Failed to fetch ANY.RUN parallel limits")
            return

        message_ids = self.queue.get_queued_messages()
        if len(message_ids) == 0:
            logger.debug("No queued messages to process")
            return

        if limits.available <= 0:
            logger.info(
                "Skipping process job: no ANY.RUN parallel slots available "
                "(total=%s, available=%s)",
                limits.total,
                limits.available,
            )
            return

        logger.info(
            "Processing %s message(s) sequentially (%s slot(s) available)",
            len(message_ids),
            limits.available,
        )

        for message_id in message_ids:
            try:
                self._process_one(message_id)
            except Exception:
                logger.exception("Unhandled error processing %s", message_id)

    # ------------------------------------------------------------------
    # Job 3: clean up messages stuck too long in local queues, and
    # reconcile PhishER tags that no longer have a matching local queue entry
    # ------------------------------------------------------------------
    def cleanup(self) -> None:
        self._cleanup_stale_queue(self.queue.message_queue_prefix, [Tags.anyrun_queued])
        self._cleanup_stale_queue(
            self.queue.inprogress_queue_prefix,
            [Tags.anyrun_queued, Tags.anyrun_pending],
        )
        self._reconcile_orphaned_tags()
