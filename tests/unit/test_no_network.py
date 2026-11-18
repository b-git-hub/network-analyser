"""The test suite itself cannot reach a network (tests/conftest.py)."""

import socket

import pytest


def test_a_test_cannot_open_a_connection() -> None:
    with pytest.raises(RuntimeError, match="never touch the network"):
        socket.create_connection(("192.0.2.1", 22), timeout=1)


def test_a_raw_socket_cannot_connect_either() -> None:
    with socket.socket() as raw, pytest.raises(RuntimeError, match="never touch the network"):
        raw.connect(("192.0.2.1", 22))
