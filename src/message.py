from typing import List

from pydantic import BaseModel

from exceptions import ObjectIsNone
from tags import Tags


class Tag(BaseModel):
    name: str
    type: str = ""

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Tag):
            return NotImplemented

        return self.name == other.name

    def __hash__(self) -> int:
        return hash(self.name)


class Event(BaseModel):
    eventType: str
    createdAt: str


class Message(BaseModel):
    message_id: str
    raw_url: str
    pipeline_status: str
    action_status: str
    tags: List[Tag]
    events: List[Event]

    has_anyrun_tag: bool

    def __init__(self, message: dict | None = None, **kwargs) -> None:
        if message is None:
            raise ObjectIsNone("`message` arg is None")

        tags = [Tag(**tag) for tag in message.get("tags", [])]
        events = [Event(**event) for event in message.get("events", [])]

        super().__init__(
            message_id=message.get("id"),
            raw_url=message.get("rawUrl"),
            pipeline_status=message.get("pipelineStatus"),
            action_status=message.get("actionStatus", "").upper(),
            tags=tags,
            events=events,
            has_anyrun_tag=self._has_anyrun_tag(tags),
            **kwargs,
        )

    @staticmethod
    def _has_anyrun_tag(tags: List[Tag]) -> bool:
        for tag in tags:
            if tag.name and tag.name.startswith(Tags.anyrun_prefix):
                return True

        return False

    def inject_tags(self, tags: List[Tag]) -> None:
        existing_names = {tag.name for tag in self.tags}

        for tag in tags:
            if tag.name not in existing_names:
                self.tags.append(tag)
                existing_names.add(tag.name)

    def erase_tags(self, tags: List[Tag]) -> None:
        names_to_remove = {tag.name for tag in tags}

        self.tags = [tag for tag in self.tags if tag.name not in names_to_remove]
