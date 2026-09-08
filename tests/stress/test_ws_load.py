import sys

from tests.stress.ws_load import parse_args


def test_managed_load_test_disables_debug_by_default(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["ws_load.py", "--managed-reset"])

    args = parse_args()

    assert args.debug is False


def test_managed_load_test_can_enable_debug(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["ws_load.py", "--managed-reset", "--debug"])

    args = parse_args()

    assert args.debug is True
