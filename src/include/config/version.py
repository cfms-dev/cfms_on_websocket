import re
from functools import total_ordering


@total_ordering
class Version:
    def __init__(self, version_str, /):
        self.original = version_str
        # Match: major.minor.patch[.build][_type][type_num]
        version_pattern = (
            r"(\d+)"  # major
            r"\.(\d+)"  # minor
            r"\.(\d+)"  # patch
            r"(?:\.(\d+))?"  # optional .build
            r"(?:_([a-zA-Z]+)"  # optional _type
            r"(\d*)?)?"  # optional type_num
        )
        # Version pattern groups:
        # (\d+) matches the major version.
        # \.(\d+) matches the minor version.
        # \.(\d+) matches the patch version.
        # (?:\.(\d+))? optionally matches the build number.
        # (?:_([a-zA-Z]+)(\d*)?)? optionally matches type and type number.
        match = re.match(version_pattern, version_str)
        if not match:
            raise ValueError(f"Invalid version string: {version_str}")
        self.major = int(match.group(1))
        self.minor = int(match.group(2))
        self.patch = int(match.group(3))
        self.build = int(match.group(4)) if match.group(4) else 0
        self.type = match.group(5) or ""
        self.type_num = int(match.group(6)) if match.group(6) else 0

        # Lower values indicate higher version type precedence.
        # Release and unspecified types have the highest precedence.
        self.type_order = {"release": 0, "": 0, "rc": 1, "beta": 2, "alpha": 3}

    def _cmp_tuple(self):
        return (
            self.major,
            self.minor,
            self.patch,
            self.build,
            self.type_order.get(self.type.lower(), 0),
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
