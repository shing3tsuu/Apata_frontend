from typing import Any

class UserAlreadyExistsError(Exception):
    pass

class UserNotRegisteredError(Exception):
    pass

class ContactAlreadyExistsError(Exception):
    pass

class InfrastructureError(Exception):
    def __init__(self, message: str, original_error: Exception | None = None):
        self.message = message
        self.original_error = original_error
        super().__init__(self.message)

class APIError(InfrastructureError):
    def __init__(self, message: str, status_code: int | None = None,
                 response_data: dict[str, Any] | None = None):
        self.status_code = status_code
        self.response_data = response_data
        super().__init__(message)

class NetworkError(InfrastructureError):
    pass

class AuthenticationError(InfrastructureError):
    pass

