"""The crash-dump guard, run before any secret is typed (spec #37, stories 18-19; #6).

The registry needs Windows, so these tests hand the guard a fake reader of HKLM keys: a dict
from (key path, registry view) to that key's values, where a missing entry is a missing key.
"""

import io
from collections.abc import Mapping

import pytest

from network_analyser._winsys.wer import RegistryUnreadableError, RegistryView
from network_analyser.cli.crash_dump_guard import AEDEBUG, LOCAL_DUMPS, guard_crash_dumps
from network_analyser.cli.prompts import Prompter

type Registry = dict[tuple[str, RegistryView], Mapping[str, object]]

# What a PC with no dump settings and no crash debugger typically holds.
CLEAN: Registry = {(AEDEBUG, RegistryView.BIT64): {"UserDebuggerHotKey": 0, "Auto": "0"}}


class FakeRegistry:
    """Reads HKLM keys from a dict, and records which ones were read."""

    def __init__(self, keys: Registry, *, unreadable: bool = False) -> None:
        self._keys = keys
        self._unreadable = unreadable
        self.read: list[tuple[str, RegistryView]] = []

    def read_machine_key(self, path: str, view: RegistryView) -> Mapping[str, object] | None:
        self.read.append((path, view))
        if self._unreadable:
            raise RegistryUnreadableError
        return self._keys.get((path, view))


class Guarded:
    """One run of the guard, with every Windows call faked."""

    def __init__(self, keys: Registry, *, answer: str = "", unreadable: bool = False) -> None:
        self.registry = FakeRegistry(keys, unreadable=unreadable)
        self.suppressed = 0
        self.stdin = io.StringIO(f"{answer}\n")
        self.stderr = io.StringIO()
        prompter = Prompter(console=None, stdin=self.stdin, stderr=self.stderr)
        self.carry_on = guard_crash_dumps(
            prompter, read_machine_key=self.registry.read_machine_key, suppress=self._suppress
        )
        self.shown = self.stderr.getvalue()

    def _suppress(self) -> None:
        self.suppressed += 1

    @property
    def asked(self) -> bool:
        return "Type YES" in self.shown


def test_with_no_dump_settings_it_carries_on_without_asking() -> None:
    run = Guarded(CLEAN)

    assert run.carry_on
    assert not run.asked
    assert run.shown == ""


def test_windows_error_reporting_is_always_suppressed_first() -> None:
    assert Guarded(CLEAN).suppressed == 1
    assert Guarded({(LOCAL_DUMPS, RegistryView.BIT64): {}}, answer="no").suppressed == 1


def test_both_registry_views_of_both_keys_are_read() -> None:
    run = Guarded(CLEAN)

    assert set(run.registry.read) == {
        (LOCAL_DUMPS, RegistryView.BIT64),
        (LOCAL_DUMPS, RegistryView.BIT32),
        (AEDEBUG, RegistryView.BIT64),
        (AEDEBUG, RegistryView.BIT32),
    }


@pytest.mark.parametrize("view", list(RegistryView))
def test_local_dumps_asks_and_yes_carries_on(view: RegistryView) -> None:
    # The LocalDumps key alone turns dumps on, with default values, for every program.
    run = Guarded({**CLEAN, (LOCAL_DUMPS, view): {}}, answer="YES")

    assert run.asked
    assert "LocalDumps" in run.shown
    assert run.carry_on


@pytest.mark.parametrize("answer", ["", "yes", "y", "Y", "no", " YES please"])
def test_anything_but_yes_stops(answer: str) -> None:
    run = Guarded({(LOCAL_DUMPS, RegistryView.BIT64): {"DumpType": 2}}, answer=answer)

    assert run.asked
    assert not run.carry_on
    assert "No secret was typed" in run.shown


def test_a_crash_debugger_that_starts_by_itself_asks() -> None:
    debugger = {"Debugger": '"C:\\Tools\\dbg.exe" -p %ld -e %ld', "Auto": "1"}
    run = Guarded({(AEDEBUG, RegistryView.BIT32): debugger}, answer="YES")

    assert run.asked
    assert "AeDebug" in run.shown
    assert "starts by itself" in run.shown
    assert run.carry_on


def test_a_crash_debugger_that_waits_to_be_chosen_still_asks() -> None:
    debugger = {"Debugger": "dbg.exe -p %ld", "Auto": 0}

    run = Guarded({(AEDEBUG, RegistryView.BIT64): debugger}, answer="no")

    assert run.asked
    assert "may offer to start it" in run.shown
    assert not run.carry_on


def test_an_empty_debugger_value_is_no_debugger() -> None:
    assert not Guarded({(AEDEBUG, RegistryView.BIT64): {"Debugger": " ", "Auto": "1"}}).asked


def test_settings_that_cannot_be_read_count_as_a_risk() -> None:
    # Fail closed: an unreadable key, or a system with no Windows registry at all.
    run = Guarded({}, unreadable=True, answer="no")

    assert run.asked
    assert "could not be read" in run.shown
    assert not run.carry_on


def test_input_that_ends_at_the_question_cancels() -> None:
    with pytest.raises(EOFError):
        guard_crash_dumps(
            Prompter(console=None, stdin=io.StringIO(""), stderr=io.StringIO()),
            read_machine_key=FakeRegistry({(LOCAL_DUMPS, RegistryView.BIT64): {}}).read_machine_key,
            suppress=lambda: None,
        )
