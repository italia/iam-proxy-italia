
class StorageError(Exception):
    def __init__(self, message="Generic error while interaction with the storage Layer"):
        self.message = message
        super().__init__(self.message)

class UnsupportedStorageEngine(StorageError):
    def __init__(self, message="The specified engine is not yet supported."):
        self.message = message
        super().__init__(self.message)

class RepositoryNotFound(StorageError):
    def __init__(self, message="Repository doesn't exist for the given engine"):
        super().__init__(message)

class StorageUnreachable(Exception):
    def __init__(self, message="Connection to database failed. The server is not reachable."):
        self.message = message
        super().__init__(self.message)


class HttpError(Exception):
    pass


class BadRequestError(Exception):
    """
    Bad Request error.

    This exception should be raised when we want to return an HTTP 400 Bad Request
    """
    pass


class InternalServerError(Exception):
    """
    Bad Request error.

    This exception should be raised when we want to return an HTTP 400 Bad Request
    """
    pass


class InvalidInternalStateError(InternalServerError):
    """
    This is specification of InternalServerError that specify that the internal
    error is caused by an invalid backend, storage or cache state.
    """
    pass


class FinalizedSessionError(BadRequestError):
    """
    Raised when an authorization request or respsonse attempts at updating or modifying
    an already finalized authentication session.
    """
    pass


class DiscoveryFailedError(Exception):
    """
    Raised when the discovery fails
    """
    pass


class HTTPError(Exception):
    """
    Raised when an error occurs during an HTTP request
    """
    pass


class EmptyHTTPError(HTTPError):
    """
    Default HTTP empty error
    """
    pass


class AuthorizeUnmatchedResponse(Exception):
    """
    Raised when an authorization response cannot be matched to an authentication request
    """
    pass

class UnknownKid(Exception):
    """
    Raised when not found kid from JWK
    """
    pass
