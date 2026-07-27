class ConnectorNotConfigured(Exception):
    pass


class NotANumber(Exception):
    pass


class ObjectIsNone(Exception):
    pass


class InvalidMessage(Exception):
    pass


class PhisherRequestError(Exception):
    pass


class AnyRunApiError(Exception):
    pass


class AnyRunParallelLimitError(AnyRunApiError):
    pass


class RedisError(Exception):
    pass
