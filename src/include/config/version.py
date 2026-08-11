import re
from functools import total_ordering

_VERSION_PATTERN = re.compile(
    r"(\d+)"  # major
    r"\.(\d+)"  # minor
    r"\.(\d+)"  # patch
    r"(?:\.(\d+))?"  # optional .build
    r"(?:_([a-zA-Z]+)"  # optional _type
    r"(\d*)?)?"  # optional type_num
)
_TYPE_ORDER = {"alpha": 0, "beta": 1, "rc": 2, "release": 3, "": 3}


@total_ordering
class Version:
    def __init__(self, version_str, /):
        self.original = version_str
        match = _VERSION_PATTERN.fullmatch(version_str)
        if not match:
            raise ValueError(f"Invalid version string: {version_str}")
        self.major = int(match.group(1))
        self.minor = int(match.group(2))
        self.patch = int(match.group(3))
        self.build = int(match.group(4)) if match.group(4) else 0
        self.type = (match.group(5) or "").lower()
        if self.type not in _TYPE_ORDER:
            raise ValueError(f"Invalid version string: {version_str}")
        self.type_num = int(match.group(6)) if match.group(6) else 0

    def _cmp_tuple(self):
        return (
            self.major,
            self.minor,
            self.patch,
            self.build,
            _TYPE_ORDER[self.type],
            self.type_num,
        )

    def __eq__(self, other):
        if not isinstance(other, Version):
            return NotImplemented
        return self._cmp_tuple() == other._cmp_tuple()

    def __lt__(self, other):
        if not isinstance(other, Version):
            return NotImplemented
        return self._cmp_tuple() < other._cmp_tuple()

    def __str__(self):
        return self.original

    def __repr__(self):
        return f"Version('{self.original}')"
