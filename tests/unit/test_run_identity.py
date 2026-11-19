"""Who ran the tool and where, for the Audit log's Run-start event (#30 section 7)."""

import os

import pytest

from network_analyser import _winsys


def test_the_pc_name_is_windows_computername(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COMPUTERNAME", "PC-A")

    assert _winsys.pc_name() == "PC-A"


def test_no_pc_name_when_windows_does_not_say(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("COMPUTERNAME", raising=False)

    assert _winsys.pc_name() is None


def test_the_account_is_domain_backslash_user(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("USERDOMAIN", "LAB")
    monkeypatch.setattr(os, "getlogin", lambda: "netops")

    assert _winsys.windows_account() == "LAB\\netops"


def test_the_account_without_a_domain_is_the_user(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("USERDOMAIN", raising=False)
    monkeypatch.setattr(os, "getlogin", lambda: "netops")

    assert _winsys.windows_account() == "netops"


def test_no_account_when_the_login_name_cannot_be_read(monkeypatch: pytest.MonkeyPatch) -> None:
    def unknown() -> str:
        raise OSError(6, "No such device or address")

    monkeypatch.setattr(os, "getlogin", unknown)

    assert _winsys.windows_account() is None
