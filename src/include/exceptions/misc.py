__all__ = [
    "NoActiveRevisionsError",
    "UserError",
    "UserNotActiveError",
]


class NoActiveRevisionsError(RuntimeError): ...


class UserError(RuntimeError): ...


class UserNotActiveError(UserError):
    def __init__(self, reason: str | None = None) -> None:
        super().__init__("User account is not active")
        self.reason = reason
