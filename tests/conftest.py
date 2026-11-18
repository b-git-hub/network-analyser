"""Shared pytest set-up: no test may reach a network (spec #37: tests need no device)."""

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
