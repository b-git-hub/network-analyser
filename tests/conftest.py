"""Shared pytest set-up: no test may reach a network or the real per-user folder.

Spec #37: tests need no device. Every test also gets its own `%LOCALAPPDATA%` and working
folder under `tmp_path`, so nothing a command creates (the per-user data folder, the lock
file, a Run folder under a relative `--runs-dir`) lands in the real profile or the repo.
"""

import socket

import pytest


class NetworkUsedInTestError(RuntimeError):
    """A test tried to open a network connection."""


def _refuse(*_args: object, **_kwargs: object) -> None:
    msg = "tests never touch the network; fake the device at the device_gateway seam"
    raise NetworkUsedInTestError(msg)


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket.socket, "connect", _refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", _refuse)
    monkeypatch.setattr(socket, "create_connection", _refuse)


@pytest.fixture(autouse=True)
def _own_per_user_folder(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path_factory.mktemp("LocalAppData")))
    monkeypatch.chdir(tmp_path_factory.mktemp("work"))
