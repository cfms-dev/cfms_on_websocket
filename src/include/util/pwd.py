__all__ = [
    "RuleRequirementsNotMetError",
    "InvalidPasswordLengthError",
    "check_passwd_requirements",
]

import re
from typing import Iterable, Optional, Sequence


class RuleRequirementsNotMetError(ValueError):
    def __init__(
        self,
        passed_count: int,
        min_passed_counts: int,
        unpassed_rules: Iterable[str] = [],
    ) -> None:
        self.passed_count = passed_count
        self.min_passed_count = min_passed_counts
        self.unpassed_rules = unpassed_rules

    def __str__(self) -> str:
        msg = (
            "Password does not meet the rule requirements: "
            f"{self.passed_count} rules passed, but at least "
            f"{self.min_passed_count} are required"
        )
        if self.unpassed_rules:
            msg += f". Unpassed rules: {', '.join(self.unpassed_rules)}"
        return msg


class InvalidPasswordLengthError(ValueError):
    def __init__(
        self,
        length: int,
        min_length: Optional[int] = None,
        max_length: Optional[int] = None,
    ) -> None:
        self.length = length
        self.min_length = min_length
        self.max_length = max_length
        assert (self.min_length and self.max_length) or (
            not self.min_length and not self.max_length
        )

    def __str__(self) -> str:

        if self.min_length and self.max_length:
            return f"Password does not meet the length requirement ({self.min_length} ~ {self.max_length})"
        else:
            return "Password does not meet the length requirement"


def check_passwd_requirements(
    passwd: str,
    min_length: int,
    max_length: int,
    rules: Optional[Sequence[str]] = None,
    min_passed_count: int = 0,
) -> None:
    length = len(passwd)
    if not (min_length <= length <= max_length):
        raise InvalidPasswordLengthError(length, min_length, max_length)

    rules = rules or []
    if not rules or min_passed_count <= 0:
        return

    if min_passed_count > len(rules):
        min_passed_count = len(rules)

    matched_rules = {rule for rule in rules if re.search(rule, passwd)}
    passed_count = len(matched_rules)

    if passed_count >= min_passed_count:
        return

    unpassed_rules = set(rules) - matched_rules

    raise RuleRequirementsNotMetError(passed_count, min_passed_count, unpassed_rules)
