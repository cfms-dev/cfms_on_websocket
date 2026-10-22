from enum import IntEnum, auto


class AuthState(IntEnum):
    NONE = auto()
    PARTIAL = auto()
    FULL = auto()
