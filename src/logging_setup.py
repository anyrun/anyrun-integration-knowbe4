import logging
import os
from logging.handlers import RotatingFileHandler

PLAIN_FORMAT = "%(asctime)s [%(levelname)s] [%(name)s]: %(message)s"


class ColorFormatter(logging.Formatter):
    """Color log lines by the subsystem that emitted them.

    Colors are picked by matching the logger name (or its dotted parents)
    against LOGGER_COLORS below, so e.g. "apscheduler.executors.default"
    still matches the "apscheduler" entry.
    """

    RESET = "\033[0m"

    LOGGER_COLORS = {
        "apscheduler": "\033[32m",  # green
        "anyrun_connector": "\033[34m",  # blue
        "phisher": "\033[38;5;208m",  # orange
    }

    def __init__(self, *args, use_color: bool = True, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)

        if not self.use_color:
            return message

        color = self._color_for(record.name)
        if color is None:
            return message

        return f"{color}{message}{self.RESET}"

    @classmethod
    def _color_for(cls, logger_name: str) -> str | None:
        for prefix, color in cls.LOGGER_COLORS.items():
            if logger_name == prefix or logger_name.startswith(prefix + "."):
                return color

        return None


def _is_scheduler_record(record: logging.LogRecord) -> bool:
    return record.name == "apscheduler" or record.name.startswith("apscheduler.")


class SchedulerOnlyFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return _is_scheduler_record(record)


class ExcludeSchedulerFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return not _is_scheduler_record(record)


def _rotating_file_handler(
    path: str, max_bytes: int, backup_count: int
) -> RotatingFileHandler:
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)

    handler = RotatingFileHandler(
        path, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter(PLAIN_FORMAT))

    return handler


def configure_logging(
    level: str,
    use_color: bool = True,
    log_dir: str = "logs",
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 2,
) -> None:
    """Set up console + rotating file logging.

    Two rotating log files are kept, each capped at `backup_count` rotated
    files plus the currently-active one (backup_count=2 -> 3 files total):
      - `scheduler.log`: everything from the `apscheduler` logger tree.
      - `app.log`: everything else (phisher, anyrun_connector, connector, ...).
    """
    resolved_level = getattr(logging, level, logging.INFO)

    root = logging.getLogger()
    root.setLevel(resolved_level)
    root.handlers = []

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(ColorFormatter(PLAIN_FORMAT, use_color=use_color))
    root.addHandler(console_handler)

    scheduler_handler = _rotating_file_handler(
        os.path.join(log_dir, "scheduler.log"), max_bytes, backup_count
    )
    scheduler_handler.addFilter(SchedulerOnlyFilter())
    root.addHandler(scheduler_handler)

    app_handler = _rotating_file_handler(
        os.path.join(log_dir, "app.log"), max_bytes, backup_count
    )
    app_handler.addFilter(ExcludeSchedulerFilter())
    root.addHandler(app_handler)
