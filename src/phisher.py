import logging
from typing import Any, Optional, Self, Union

import requests

from const import (
    DISCOVERY_PER_PAGE,
    INGESTION_TAG,
    PHISHER_API_TOKEN,
    PHISHER_ENDPOINT,
    PHISHER_MESSAGE_FILTER,
    PHISHER_REQUEST_TIMEOUT,
)
from exceptions import InvalidMessage, PhisherRequestError
from message import Message, Tag
from tags import Tags

logger = logging.getLogger(__name__)


class Phisher:
    def __init__(self) -> None:
        self.endpoint = PHISHER_ENDPOINT
        self.timeout = PHISHER_REQUEST_TIMEOUT
        self.api_token = PHISHER_API_TOKEN
        self.discovery_per_page = DISCOVERY_PER_PAGE
        self.query_filter = Tags.build_discovery_query(
            PHISHER_MESSAGE_FILTER, INGESTION_TAG
        )

        self._session: Optional[requests.Session] = None

    def __enter__(self) -> Self:
        self._open_session()
        return self

    def __exit__(self, item_type, value, traceback) -> None:
        self._close_session()

    def _open_session(self) -> None:
        if not self._session:
            self._session = requests.Session()
            self._session.headers = {
                "Authorization": f"Bearer {self.api_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }

    def _close_session(self) -> None:
        if self._session:
            self._session.close()
            self._session = None

    def _make_request(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
    ) -> Union[dict, list[dict]]:
        try:
            response: requests.Response = self._session.request(
                method="POST",
                url=self.endpoint,
                json={"query": query, "variables": variables or {}},
                timeout=self.timeout,
            )

            response.raise_for_status()

            return response.json()["data"]

        except Exception as e:
            raise PhisherRequestError(
                f"Request to PhishER was unsuccessful. Details: {e}"
            )

    def list_messages(
        self,
        page: int,
        query: str | None = None,
        per: int | None = None,
        sort_direction: str = "DESCENDING",
    ) -> tuple[list[Message], dict[str, Any]]:
        graphql_query = """
        query GetMessages($query: String!, $page: Int!, $per: Int!) {
          phisherMessages(
            query: $query
            page: $page
            per: $per
            sortField: REPORTED_AT
            sortDirection: %s
          ) {
            nodes {
              id
              rawUrl
              pipelineStatus
              actionStatus
              tags { name type }
              events { eventType createdAt }
            }
            pagination { page pages per totalCount }
          }
        }
        """.replace("%s", sort_direction)
        data = self._make_request(
            graphql_query,
            {
                "query": query if query is not None else self.query_filter,
                "page": page,
                "per": per if per is not None else self.discovery_per_page,
            },
        )
        cursor = data["phisherMessages"]
        raw_messages = cursor["nodes"]
        msgs = [Message(msg) for msg in raw_messages]

        logger.debug(
            "Fetched %s message(s) on page %s/%s",
            len(msgs),
            page,
            cursor["pagination"].get("pages"),
        )

        return msgs, cursor["pagination"]

    def get_message(self, message_id: str) -> Message:
        query = """
        query GetMessage($id: String!) {
          phisherMessage(id: $id) {
            id
            rawUrl
            pipelineStatus
            actionStatus
            tags { name type }
            events { eventType createdAt }
          }
        }
        """
        data = self._make_request(query, {"id": message_id})

        try:
            msg = Message(message=data["phisherMessage"])
        except Exception as e:
            raise InvalidMessage(f"Can't process message. Details: {e}")

        return msg

    def add_tags(self, message: Message, tags: list[str]) -> None:
        if not tags:
            return

        query = """
        mutation AddTags($id: String!, $tags: [String!]!) {
          phisherTagsCreate(id: $id, tags: $tags) {
            nodes { name type }
            errors { field reason }
          }
        }
        """

        try:
            data = self._make_request(query, {"id": message.message_id, "tags": tags})
            errors = data["phisherTagsCreate"].get("errors") or []
            if errors:
                raise PhisherRequestError(f"phisherTagsCreate errors: {errors}")

            message.inject_tags([Tag(name=name) for name in tags])
            logger.debug("Added tags %s to message %s", tags, message.message_id)
        except Exception as e:
            raise PhisherRequestError(f"Can't add tags. Details: {e}")

    def remove_tags(self, message: Message, tags: list[str]) -> None:
        if not tags:
            return

        query = """
        mutation RemoveTags($id: String!, $tags: [String!]!) {
          phisherTagsDelete(id: $id, tags: $tags) {
            nodes { name type }
            errors { field reason }
          }
        }
        """

        try:
            data = self._make_request(query, {"id": message.message_id, "tags": tags})
            errors = data["phisherTagsDelete"].get("errors") or []
            if errors:
                raise PhisherRequestError(f"phisherTagsDelete errors: {errors}")

            message.erase_tags([Tag(name=name) for name in tags])
            logger.debug("Removed tags %s from message %s", tags, message.message_id)
        except Exception as e:
            raise PhisherRequestError(f"Can't remove tags. Details: {e}")

    def set_category(self, message: Message, category: str) -> None:
        query = """
        mutation UpdateMessageCategory($id: String!, $payload: MessageUpdateAttributes!) {
          phisherMessageUpdate(id: $id, payload: $payload) {
            node { id }
            errors { field reason }
          }
        }
        """
        try:
            data = self._make_request(
                query, {"id": message.message_id, "payload": {"category": category}}
            )
            errors = data["phisherMessageUpdate"].get("errors") or []
            if errors:
                raise PhisherRequestError(f"phisherMessageUpdate errors: {errors}")

            logger.debug("Set category %s on message %s", category, message.message_id)
        except Exception as e:
            raise PhisherRequestError(f"Can't set category. Details: {e}")

    def add_comment(self, message: Message, comment: str) -> None:
        query = """
        mutation AddComment($id: String!, $comment: String!) {
          phisherCommentCreate(id: $id, comment: $comment) {
            node { body createdAt }
            errors { field reason }
          }
        }
        """
        try:
            data = self._make_request(
                query, {"id": message.message_id, "comment": comment}
            )
            errors = data["phisherCommentCreate"].get("errors") or []
            if errors:
                raise PhisherRequestError(f"phisherCommentCreate errors: {errors}")

            logger.debug("Added comment to message %s", message.message_id)
        except Exception as e:
            raise PhisherRequestError(f"Can't add comment. Details: {e}")
