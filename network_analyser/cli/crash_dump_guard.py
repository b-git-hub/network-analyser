"""The crash-dump guard, run before any secret is typed (spec #37, stories 18-19; #6, #15).

Python cannot wipe memory, so a crash dump of the process could hold a Credential Set
password, the Backup Passphrase or a decrypted config. The guard first stops Windows Error
Reporting for the process (no registry write). It then reads, never writes, the HKLM
settings that could still keep a dump: WER `LocalDumps` and the AeDebug crash debugger, in
both registry views. If any could, or if they cannot be read, the operator must type `YES`
to carry on. Anything else stops before a secret is typed: the caller exits 2.
"""

from collections.abc import Callable, Mapping

from network_analyser import _winsys
from network_analyser._winsys.wer import RegistryUnreadableError, RegistryView
from network_analyser.cli.prompts import Prompter

LOCAL_DUMPS = r"SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps"
AEDEBUG = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug"

type ReadMachineKey = Callable[[str, RegistryView], Mapping[str, object] | None]

_LOCAL_DUMPS_RISK = "Windows Error Reporting is set to keep local crash dumps (LocalDumps)."
_DEBUGGER_STARTS_RISK = "A crash debugger is set up (AeDebug), and it starts by itself."
_DEBUGGER_OFFERED_RISK = "A crash debugger is set up (AeDebug), and Windows may offer to start it."
_UNREADABLE_RISK = "The crash-dump settings could not be read, so a crash dump cannot be ruled out."


def guard_crash_dumps(
    prompter: Prompter,
    *,
    read_machine_key: ReadMachineKey = _winsys.read_machine_key,
    suppress: Callable[[], None] = _winsys.suppress_error_reporting,
) -> bool:
    """Say whether to carry on to the secret prompts; ask the operator if a dump could be kept.

    Args:
        prompter: asks the operator to type YES.
        read_machine_key: reads one HKLM key. A seam for tests: the real one needs Windows.
        suppress: stops Windows Error Reporting for this process. A seam for tests.

    Raises:
        KeyboardInterrupt: the operator pressed Ctrl+C at the question.
        EOFError: input ended before an answer was given.
    """
    suppress()
    risks = _risks(read_machine_key)
    if not risks:
        return True
    prompter.say("WARNING: Windows on this PC could keep a crash dump of Network Analyser:")
    for risk in risks:
        prompter.say(f"  - {risk}")
    prompter.say(
        "If the tool crashed, a dump could hold the secrets you are about to type. Ask your\n"
        "desktop team to remove the setting, or carry on at your own risk."
    )
    if prompter.line("Type YES to carry on; anything else stops: ") == "YES":
        return True
    prompter.say("Stopped at the crash-dump check. No secret was typed.")
    return False


def _risks(read_machine_key: ReadMachineKey) -> list[str]:
    risks: list[str] = []
    try:
        for view in RegistryView:
            if read_machine_key(LOCAL_DUMPS, view) is not None:
                risks.append(_LOCAL_DUMPS_RISK)
            debugger = _debugger_risk(read_machine_key(AEDEBUG, view))
            if debugger is not None:
                risks.append(debugger)
    except RegistryUnreadableError:
        risks.append(_UNREADABLE_RISK)
    return list(dict.fromkeys(risks))  # each risk once, in the order found


def _debugger_risk(aedebug: Mapping[str, object] | None) -> str | None:
    if aedebug is None:
        return None
    debugger = aedebug.get("Debugger")
    if not (isinstance(debugger, str) and debugger.strip()):
        return None
    starts_by_itself = str(aedebug.get("Auto", "0")).strip() == "1"
    return _DEBUGGER_STARTS_RISK if starts_by_itself else _DEBUGGER_OFFERED_RISK
