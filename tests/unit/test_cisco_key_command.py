"""`network-analyser cisco-key set|show|remove` and its key lifecycle (ticket #103; ADR 0008).

Driven through `cli.main` with what the operator types on stdin. Standard input is not a
console in tests, so each prompt reads one line; on Linux the crash-dump guard always asks for
`YES`. The fake Cisco serves the token-only check at the `advisories` transport seam, and the
fast fake age stands in for scrypt.
"""

import io
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from network_analyser import backup_store, run_output
from network_analyser.cli import main
from network_analyser.credentials import Secret, SecretScan
from tests.support import fake_age
from tests.support.fake_cisco import CLIENT_ID, CLIENT_SECRET, FakeCisco
from tests.support.run_driver import (
    DEVICE_CANARY,
    FLAGS,
    Runner,
    data_folder,
    first_run,
    typed,
)

PASS = "CANARY-pp-103-c1sco"
NEW = "CANARY-pp-103-n3w00"
OTHER = "CANARY-pp-103-0ther"
WRONG = "CANARY-pp-103-wr0ng"
SET_AT = datetime(2026, 11, 20, 12, 34, 56, tzinfo=UTC)
STAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")


@dataclass(frozen=True)
class Outcome:
    code: int
    out: str
    err: str


@pytest.fixture(autouse=True)
def _fake(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_age.use_fake_age(monkeypatch)


def _serve_with(monkeypatch: pytest.MonkeyPatch, fake: FakeCisco) -> FakeCisco:
    """Make the real token request go to `fake` instead of Cisco."""
    monkeypatch.setattr(
        "network_analyser.advisories.session.HttpsTransport", lambda **_kwargs: fake
    )
    return fake


class Operator:
    """The operator's per-user data folder and the command itself."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
        self.data = data_folder()
        self.monkeypatch = monkeypatch
        self.capsys = capsys
        self.passphrase = backup_store.create_check_file(self.data.check_file, Secret(PASS))

    def __call__(self, *argv: str, typed: str = "") -> Outcome:
        self.monkeypatch.setattr("sys.stdin", io.StringIO(typed))
        code = main(["cisco-key", *argv])
        captured = self.capsys.readouterr()
        return Outcome(code, captured.out, captured.err)

    def store(self) -> None:
        """Store a key directly, without the prompts, as another command would leave it."""
        backup_store.lock_key_file(
            self.data.cisco_key_file,
            Secret(CLIENT_ID),
            Secret(CLIENT_SECRET),
            self.passphrase,
            set_at=SET_AT,
        )


@pytest.fixture
def operator(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> Operator:
    return Operator(monkeypatch, capsys)


def _flat(text: str) -> str:
    return " ".join(text.split())


# -- set (stories 23-29) ----------------------------------------------------------------------


def test_set_stores_the_key_and_reports_the_accepted_check(
    operator: Operator, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _serve_with(monkeypatch, FakeCisco())

    got = operator("set", typed=typed("YES", PASS, CLIENT_ID, CLIENT_SECRET))

    assert got.code == 0, got.err
    assert fake.token_calls() == 1
    assert fake.api_requests() == []
    key = backup_store.unlock_key_file(operator.data.cisco_key_file, operator.passphrase)
    assert key is not None
    assert key.client_id.same_as(Secret(CLIENT_ID))
    assert key.client_secret.same_as(Secret(CLIENT_SECRET))
    assert "Cisco accepted the API key" in _flat(got.err)


def test_set_takes_the_passphrase_first_and_stores_nothing_after_three_wrong_ones(
    operator: Operator,
) -> None:
    got = operator("set", typed=typed("YES", WRONG, WRONG, WRONG))

    assert got.code == 2
    assert "try 3 of 3" in got.err
    assert "client ID" not in got.err
    assert not operator.data.cisco_key_file.exists()


def test_set_refuses_when_there_is_no_check_file(operator: Operator) -> None:
    operator.data.check_file.unlink()

    got = operator("set", typed="")

    assert got.code == 2
    assert "first Run sets it" in got.err
    assert "client ID" not in got.err
    assert not operator.data.cisco_key_file.exists()


def test_set_takes_the_client_id_and_secret_at_masked_prompts(
    operator: Operator, monkeypatch: pytest.MonkeyPatch
) -> None:
    _serve_with(monkeypatch, FakeCisco())

    got = operator("set", typed=typed("YES", PASS, CLIENT_ID, CLIENT_SECRET))

    assert got.code == 0, got.err
    assert "Backup Passphrase" in got.err
    assert "client ID" in got.err
    assert "client secret" in got.err
    assert CLIENT_ID not in got.out + got.err
    assert CLIENT_SECRET not in got.out + got.err
    assert got.err.index("Backup Passphrase") < got.err.index("client ID")


def test_a_client_id_given_as_an_option_is_refused_without_echoing_it(
    operator: Operator,
) -> None:
    got = operator("set", "--client-id", CLIENT_ID)

    assert got.code == 2
    assert CLIENT_ID not in got.out + got.err
    assert "unrecognized arguments (not shown)" in got.err


def test_set_shows_the_least_privilege_guidance(operator: Operator) -> None:
    got = operator("set", "--no-check", typed=typed("YES", PASS, CLIENT_ID, CLIENT_SECRET))

    guidance = _flat(got.err)
    for words in (
        "one Service app",
        "client-credentials",
        "only the three APIs ticked",
        "openVuln, EoX and Software Suggestion",
        "end date on the API Developer role",
        "registration email deleted",
    ):
        assert words in guidance


def test_set_wipes_the_passphrase_and_the_key_from_memory(
    operator: Operator, monkeypatch: pytest.MonkeyPatch
) -> None:
    _serve_with(monkeypatch, FakeCisco())
    wiped: list[Secret] = []
    real_wipe = Secret.wipe
    forgot: list[SecretScan] = []

    def spy(self: Secret) -> None:
        wiped.append(self)
        real_wipe(self)

    def forget(self: SecretScan) -> None:
        forgot.append(self)

    monkeypatch.setattr(Secret, "wipe", spy)
    monkeypatch.setattr(SecretScan, "forget", forget)

    got = operator("set", typed=typed("YES", PASS, CLIENT_ID, CLIENT_SECRET))

    assert got.code == 0, got.err
    assert len(wiped) >= 3  # the passphrase, the client ID and the client secret
    assert len(forgot) == 1


def test_set_no_check_stores_the_key_without_asking_cisco(
    operator: Operator, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _serve_with(monkeypatch, FakeCisco())

    got = operator("set", "--no-check", typed=typed("YES", PASS, CLIENT_ID, CLIENT_SECRET))

    assert got.code == 0, got.err
    assert fake.requests == []
    assert "Skipped the online check" in got.err
    assert operator.data.cisco_key_file.is_file()


def test_set_reports_a_rejected_key_and_keeps_it_stored(
    operator: Operator, monkeypatch: pytest.MonkeyPatch
) -> None:
    _serve_with(monkeypatch, FakeCisco(token_status=400, token_error="invalid_client"))

    got = operator("set", typed=typed("YES", PASS, CLIENT_ID, CLIENT_SECRET))

    assert got.code == 1
    assert "rejected the API key" in got.err
    assert "HTTP 400" in got.err
    assert "invalid_client" in got.err
    assert "cisco-key set" in got.err
    assert operator.data.cisco_key_file.is_file()


def test_set_reports_an_outage_and_keeps_it_stored(
    operator: Operator, monkeypatch: pytest.MonkeyPatch
) -> None:
    _serve_with(monkeypatch, FakeCisco(outage=True))

    got = operator("set", typed=typed("YES", PASS, CLIENT_ID, CLIENT_SECRET))

    assert got.code == 1
    assert "did not answer the key check" in got.err
    assert operator.data.cisco_key_file.is_file()


def test_set_passes_the_proxy_to_the_token_check(
    operator: Operator, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`--proxy` must reach the one online request `set` makes, as `run --proxy` does (#150)."""
    fake = FakeCisco()
    opened: dict[str, Any] = {}

    def transport(**kwargs: object) -> FakeCisco:
        opened.update(kwargs)
        return fake

    monkeypatch.setattr("network_analyser.advisories.session.HttpsTransport", transport)

    got = operator(
        "set",
        "--proxy",
        "proxy.example:8080",
        typed=typed("YES", PASS, CLIENT_ID, CLIENT_SECRET),
    )

    assert got.code == 0, got.err
    proxy = opened["proxy"]
    assert proxy.address == "proxy.example:8080"
    assert fake.token_calls() == 1


# -- show (story 30) --------------------------------------------------------------------------


def test_show_says_when_the_key_was_set_without_asking_for_the_passphrase(
    operator: Operator,
) -> None:
    """Story 30: only the last 4 needs the passphrase, so plain `show` never asks for it (#150)."""
    operator.store()

    got = operator("show", typed="")

    assert got.code == 0, got.err
    assert "A Cisco API key is stored" in got.out
    assert STAMP.search(got.out)
    assert "The client ID ends in" not in got.out
    assert "Backup Passphrase" not in got.err


def test_show_says_when_the_key_was_set_and_the_last_four_with_the_passphrase(
    operator: Operator,
) -> None:
    operator.store()

    got = operator("show", "--last-4", typed=typed("YES", PASS))

    assert got.code == 0, got.err
    assert "A Cisco API key is stored" in got.out
    assert STAMP.search(got.out)
    assert f"The client ID ends in {CLIENT_ID[-4:]}." in got.out
    assert CLIENT_ID not in got.out + got.err
    assert CLIENT_SECRET not in got.out + got.err


def test_show_says_no_key_is_stored_without_asking_for_anything(operator: Operator) -> None:
    got = operator("show", typed="")

    assert got.code == 0
    assert "No Cisco API key is stored" in got.out
    assert "Backup Passphrase" not in got.err


def test_show_does_not_show_last_four_after_three_wrong_passphrases(operator: Operator) -> None:
    operator.store()

    got = operator("show", "--last-4", typed=typed("YES", WRONG, WRONG, WRONG))

    assert got.code == 2
    assert "The client ID ends in" not in got.out
    assert CLIENT_ID not in got.out + got.err
    assert CLIENT_SECRET not in got.out + got.err


def test_show_reports_a_key_locked_elsewhere_once(operator: Operator, tmp_path: Path) -> None:
    other = backup_store.create_check_file(tmp_path / "other" / "check.age", Secret(OTHER))
    backup_store.lock_key_file(
        operator.data.cisco_key_file,
        Secret(CLIENT_ID),
        Secret(CLIENT_SECRET),
        other,
        set_at=SET_AT,
    )

    got = operator("show", "--last-4", typed=typed("YES", PASS))

    assert got.code == 1
    assert (got.out + got.err).count(backup_store.KEY_LOCKED_ELSEWHERE) == 1


def test_show_reports_an_unreadable_key_file_as_unreadable(operator: Operator) -> None:
    operator.data.cisco_key_file.write_bytes(b"x" * (64 * 1024 + 1))

    got = operator("show", "--last-4", typed=typed("YES", PASS))

    assert got.code == 1
    assert backup_store.KEY_FILE_UNREADABLE in got.err
    assert backup_store.KEY_LOCKED_ELSEWHERE not in got.err


# -- remove (story 31) ------------------------------------------------------------------------


def test_remove_deletes_the_key_after_a_yes(operator: Operator) -> None:
    operator.store()

    got = operator("remove", typed=typed("y"))

    assert got.code == 0, got.err
    assert "Cisco API key removed" in got.err
    assert not operator.data.cisco_key_file.exists()


@pytest.mark.parametrize("answer", ["", "n"])
def test_remove_keeps_the_key_without_a_yes(operator: Operator, answer: str) -> None:
    operator.store()

    got = operator("remove", typed=typed(answer))

    assert got.code == 3
    assert "[y/N]" in got.err
    assert "Cancelled" in got.err
    assert operator.data.cisco_key_file.is_file()


def test_remove_says_no_key_is_stored(operator: Operator) -> None:
    got = operator("remove", typed="")

    assert got.code == 0
    assert "No Cisco API key is stored" in got.out


# -- Story 32: never during a Run -------------------------------------------------------------


@pytest.mark.parametrize("action", ["set", "show", "remove"])
def test_every_action_refuses_while_another_command_holds_the_lock(
    operator: Operator, action: str
) -> None:
    lock = run_output.take_instance_lock(operator.data)
    assert lock is not None
    try:
        got = operator(action, typed="")
    finally:
        lock.release()

    assert got.code == 2
    assert "in progress" in got.err
    assert not operator.data.cisco_key_file.exists()


@pytest.mark.parametrize("action", ["set", "show", "remove"])
def test_every_action_refuses_when_another_account_can_reach_the_trust_folder(
    operator: Operator, monkeypatch: pytest.MonkeyPatch, action: str
) -> None:
    monkeypatch.setattr(
        "network_analyser.cli.trust_folder.run_output.check_trust_folder",
        lambda *_args, **_kwargs: run_output.TrustFolderCheck(
            refusal="accounts other than you can read or change it", warning=None
        ),
    )

    got = operator(action, typed="")

    assert got.code == 2
    assert "refused" in got.err
    assert "Backup Passphrase" not in got.err


# -- The lifecycle: change-passphrase and starting over (stories 37, 39) ----------------------


def test_change_passphrase_forgets_the_scanned_secrets(
    operator: Operator, monkeypatch: pytest.MonkeyPatch
) -> None:
    operator.store()
    forgot: list[SecretScan] = []

    def forget(self: SecretScan) -> None:
        forgot.append(self)

    monkeypatch.setattr(SecretScan, "forget", forget)

    operator.monkeypatch.setattr("sys.stdin", io.StringIO(typed("YES", PASS, NEW, NEW, "y")))
    code = main(["change-passphrase"])
    operator.capsys.readouterr()

    assert code == 0
    assert len(forgot) == 1


def test_change_passphrase_relocks_the_key_with_the_new_passphrase(operator: Operator) -> None:
    operator.store()
    operator.monkeypatch.setattr("sys.stdin", io.StringIO(typed("YES", PASS, NEW, NEW, "y")))
    code = main(["change-passphrase"])
    got = operator.capsys.readouterr()

    new = backup_store.unlock_check_file(operator.data.check_file, Secret(NEW))
    assert new is not None
    assert code == 0, got.err
    assert backup_store.unlock_key_file(operator.data.cisco_key_file, new) is not None
    assert backup_store.unlock_key_file(operator.data.cisco_key_file, operator.passphrase) is None


def test_change_passphrase_reports_a_key_locked_elsewhere(
    operator: Operator, tmp_path: Path
) -> None:
    other = backup_store.create_check_file(tmp_path / "other" / "check.age", Secret(OTHER))
    backup_store.lock_key_file(
        operator.data.cisco_key_file,
        Secret(CLIENT_ID),
        Secret(CLIENT_SECRET),
        other,
        set_at=SET_AT,
    )

    operator.monkeypatch.setattr("sys.stdin", io.StringIO(typed("YES", PASS, NEW, NEW, "y")))
    code = main(["change-passphrase"])
    got = operator.capsys.readouterr()

    assert code == 1
    assert backup_store.KEY_LOCKED_ELSEWHERE in got.out
    assert backup_store.unlock_key_file(operator.data.cisco_key_file, other) is not None


def test_starting_over_deletes_the_stored_key(operator: Operator) -> None:
    operator.store()
    operator.data.check_file.unlink()  # the operator starts over by hand

    got = Runner(operator.monkeypatch, operator.capsys)(*FLAGS, typed=first_run(start="n"))

    assert got.code == 3
    assert not operator.data.cisco_key_file.exists()
    assert operator.data.check_file.is_file()


def test_a_run_with_a_check_file_keeps_the_stored_key(operator: Operator) -> None:
    operator.store()

    answers = typed("YES", PASS, "netops-ro", DEVICE_CANARY, "", "n", "n")
    got = Runner(operator.monkeypatch, operator.capsys)(*FLAGS, typed=answers)

    assert got.code == 3
    assert operator.data.cisco_key_file.is_file()
