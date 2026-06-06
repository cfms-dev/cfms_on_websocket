__all__ = [
    "NoActiveRevisionsError",
    "UserError",
    "UserNotActiveError",
    "UserTOTPRequiredError",
    "UserTOTPFailedError",
]


class NoActiveRevisionsError(RuntimeError): ...


class UserError(RuntimeError): ...


class UserNotActiveError(UserError): ...


class UserTOTPRequiredError(UserError): ...


class UserTOTPFailedError(UserError): ...
