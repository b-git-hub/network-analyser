"""PROTOTYPE - throwaway. Not production code. Delete once the question is settled.

Question (wayfinder ticket "How the operator enters Credential Sets at Run start",
https://github.com/b-git-hub/network-analyser/issues/15):

    Is a hidden console prompt at Run start workable, or should the tool also
    read Credential Sets the operator created in Windows Credential Manager?

Four flows you can switch between from the launcher menu:

    A  Step by step    - each Credential Set asked in full, one after another
    B  Review screen   - type username/password pairs fast, then edit a table
    C  Passwords only  - usernames and Platform limits come from the command
                         line, so only passwords are typed
    D  Credential Manager (SIMULATED) - what it would feel like if passwords
                         were read from Windows Credential Manager instead

Every flow keeps the prompt order from ADR 0004: crash-dump warning, then the
Backup Passphrase, then the Credential Sets.

Run it (Windows, Python 3.10+, standard library only):

    py prototypes\\credentials\\credential_prompt_prototype.py
    py prototypes\\credentials\\credential_prompt_prototype.py --set netops-ro --set svc-nexus:nxos

Nothing is written to disk. No device is contacted. Nothing is read from Credential
Manager or the registry: the crash-dump risk and the Credential Manager entries are
simulated. The Backup Passphrase "check file" lives in memory only, so the first pass
through any flow is a first Run and later passes are returning Runs.
"""

from __future__ import annotations

import argparse
import getpass
import sys
import time
from dataclasses import dataclass, field

PLATFORMS = ["IOS/IOS-XE", "NX-OS"]
PLATFORM_CODES = {"ios": "IOS/IOS-XE", "iosxe": "IOS/IOS-XE", "nxos": "NX-OS"}
MAX_SETS = 5
MIN_PASSPHRASE = 15
MAX_BUDGET = 5


class StopRun(Exception):
    """The Run stops before any device is contacted."""


# ---------------------------------------------------------------- state


@dataclass
class CredentialSet:
    username: str
    password: str = field(repr=False)
    platforms: list[str] = field(default_factory=list)  # empty = any Platform

    def limit_text(self) -> str:
        return ", ".join(self.platforms) + " only" if self.platforms else "any Platform"


@dataclass
class RunStart:
    variant: str
    passphrase: str | None = field(default=None, repr=False)
    sets: list[CredentialSet] = field(default_factory=list)
    failure_budget: int = 3
    dump_warning_accepted: bool | None = None


@dataclass
class Session:
    """What survives between passes in this process (never written anywhere)."""

    check_passphrase: str | None = field(default=None, repr=False)  # stands in for the check file
    mask: bool = False
    dump_risk: bool = False
    failure_budget: int = 3
    cli_sets: list[tuple[str, list[str]]] = field(default_factory=list)


def show_state(run: RunStart, note: str = "") -> None:
    print()
    print("   .-- in memory now " + "-" * 44)
    if note:
        print(f"   | changed: {note}")
    dump = {None: "not checked yet", True: "risk accepted by operator", False: "no dump settings found"}
    print(f"   | crash-dump check : {dump[run.dump_warning_accepted]}")
    print(f"   | Backup Passphrase: {'held (hidden)' if run.passphrase else '-'}")
    print(f"   | failure budget   : {run.failure_budget} failed logins per set, then Retired")
    if not run.sets:
        print("   | Credential Sets  : none yet")
    for i, s in enumerate(run.sets, 1):
        pw = "password held (hidden)" if s.password else "NO PASSWORD"
        print(f"   | set {i}: {s.username:<18} {pw:<23} {s.limit_text()}")
    print("   '" + "-" * 63)
    print()


# ---------------------------------------------------------------- input


def read_secret(prompt: str, mask: bool) -> str:
    """Hidden input. With mask on, Windows shows one * per character typed or pasted."""
    if not mask:
        return getpass.getpass(prompt)
    try:
        import msvcrt  # Windows only
    except ImportError:
        if sys.version_info >= (3, 14):
            return getpass.getpass(prompt, echo_char="*")
        print("   (masking needs Windows or Python 3.14; falling back to fully hidden)")
        return getpass.getpass(prompt)
    sys.stdout.write(prompt)
    sys.stdout.flush()
    chars: list[str] = []
    while True:
        ch = msvcrt.getwch()
        if ch in ("\r", "\n"):
            sys.stdout.write("\n")
            return "".join(chars)
        if ch == "\x03":
            raise KeyboardInterrupt
        if ch in ("\x00", "\xe0"):  # arrow/function key: swallow the second code
            msvcrt.getwch()
            continue
        if ch == "\x08":
            if chars:
                chars.pop()
                sys.stdout.write("\b \b")
        else:
            chars.append(ch)
            sys.stdout.write("*")
        sys.stdout.flush()


def ask(prompt: str) -> str:
    return input(prompt).strip()


def ask_platforms(username: str) -> list[str]:
    print(f"   Limit {username} to a Platform?  1) IOS/IOS-XE   2) NX-OS   Enter) any Platform")
    while True:
        raw = ask("   Choice (e.g. 1, 2, 1,2 or Enter): ")
        if not raw:
            return []
        try:
            picks = sorted({int(p) for p in raw.replace(" ", "").split(",")})
            if all(1 <= p <= len(PLATFORMS) for p in picks):
                chosen = [PLATFORMS[p - 1] for p in picks]
                return [] if len(chosen) == len(PLATFORMS) else chosen
        except ValueError:
            pass
        print("   Not a valid choice.")


def ask_device_password(username: str, run: RunStart, mask: bool) -> str:
    while True:
        pw = read_secret(f"   Password for {username}: ", mask)
        if not pw:
            print("   A Credential Set needs a password. Try again (Ctrl+C cancels the Run).")
            continue
        if pw == run.passphrase:
            # ADR 0004: the Backup Passphrase must differ from every Credential Set password.
            # The device password cannot be changed at this prompt, so the Run has to stop.
            raise StopRun(
                f"The password for {username} is the same as the Backup Passphrase.\n"
                "   The Backup Passphrase must differ from every device password.\n"
                "   Change the Backup Passphrase, then start the Run again."
            )
        return pw


# ---------------------------------------------------------------- common opening steps


def crash_dump_step(run: RunStart, session: Session) -> None:
    print("Step 1 - crash-dump check (SIMULATED: nothing was read from the registry)")
    if not session.dump_risk:
        print("   Windows is not set to keep crash dumps of this program. Carrying on.")
        run.dump_warning_accepted = False
        show_state(run, "crash-dump check passed")
        return
    print("   WARNING: Windows on this PC is set to keep crash dumps of programs")
    print("   (Windows Error Reporting LocalDumps). If Network Analyser crashed, a dump")
    print("   could hold the passwords you are about to type. Ask your desktop team to")
    print("   remove the LocalDumps setting, or carry on at your own risk.")
    if ask("   Type YES to carry on, anything else stops: ") != "YES":
        raise StopRun("Stopped at the crash-dump warning. No password was typed.")
    run.dump_warning_accepted = True
    show_state(run, "operator accepted the crash-dump risk")


def passphrase_step(run: RunStart, session: Session) -> None:
    print("Step 2 - Backup Passphrase")
    if session.check_passphrase is None:
        print("   First Run: choose the Backup Passphrase that locks every Backup.")
        print(f"   At least {MIN_PASSPHRASE} characters. There is NO recovery: forget it and every")
        print("   Backup it locked is lost. Keep it in your password manager.")
        for _ in range(3):
            first = read_secret("   New Backup Passphrase: ", session.mask)
            if len(first) < MIN_PASSPHRASE:
                print(f"   Too short ({MIN_PASSPHRASE} characters minimum).")
                continue
            if read_secret("   Type it again: ", session.mask) != first:
                print("   The two entries differ.")
                continue
            session.check_passphrase = first  # stands in for writing the check file
            run.passphrase = first
            show_state(run, "Backup Passphrase set; check file created (simulated, in memory)")
            return
        raise StopRun("No Backup Passphrase was set after 3 tries.")
    for attempt in range(1, 4):
        pp = read_secret("   Backup Passphrase: ", session.mask)
        if pp == session.check_passphrase:
            run.passphrase = pp
            show_state(run, "Backup Passphrase unlocked the check file")
            return
        print(f"   That does not unlock the check file (try {attempt} of 3).")
    raise StopRun("The Backup Passphrase did not unlock the check file. No device password was typed.")


def confirm_start(run: RunStart, started: float) -> None:
    print("Ready to start the Run with:")
    show_state(run)
    print(f"   Time spent at the prompts: {time.monotonic() - started:.0f} s")
    if ask("   Start the Run? [Y/n]: ").lower() in ("n", "no"):
        raise StopRun("Operator chose not to start.")
    print("\n   (prototype) The Run would start now. Every secret is dropped when it ends.")


# ---------------------------------------------------------------- variant A: step by step


def variant_a(run: RunStart, session: Session) -> None:
    print(f"Step 3 - Credential Sets (up to {MAX_SETS}), tried in the order you give them")
    while len(run.sets) < MAX_SETS:
        n = len(run.sets) + 1
        username = ask(f"   Set {n} username: ")
        if not username:
            if run.sets:
                break
            print("   At least one Credential Set is needed.")
            continue
        pw = ask_device_password(username, run, session.mask)
        platforms = ask_platforms(username)
        run.sets.append(CredentialSet(username, pw, platforms))
        show_state(run, f"set {n} added")
        if len(run.sets) < MAX_SETS and ask("   Add another Credential Set? [y/N]: ").lower() not in ("y", "yes"):
            break


# ---------------------------------------------------------------- variant B: review screen


def variant_b(run: RunStart, session: Session) -> None:
    print(f"Step 3 - Credential Sets: type up to {MAX_SETS} username/password pairs.")
    print("   Press Enter on an empty username when done. You can edit the list next.")
    while len(run.sets) < MAX_SETS:
        username = ask(f"   [{len(run.sets) + 1}] username: ")
        if not username:
            if run.sets:
                break
            print("   At least one Credential Set is needed.")
            continue
        run.sets.append(CredentialSet(username, ask_device_password(username, run, session.mask)))
    while True:
        show_state(run)
        print("   Edit:  p N  set Platform limit   d N  delete   u N  move up")
        print(f"          a    add a set           b N  failure budget (1-{MAX_BUDGET})")
        print("          s    done")
        cmd = ask("   > ").split()
        if not cmd:
            continue
        op, arg = cmd[0].lower(), (cmd[1] if len(cmd) > 1 else "")
        idx = int(arg) - 1 if arg.isdigit() else -1
        if op == "s":
            if run.sets:
                return
            print("   At least one Credential Set is needed.")
        elif op == "a" and len(run.sets) < MAX_SETS:
            username = ask("   username: ")
            if username:
                run.sets.append(CredentialSet(username, ask_device_password(username, run, session.mask)))
        elif op == "p" and 0 <= idx < len(run.sets):
            run.sets[idx].platforms = ask_platforms(run.sets[idx].username)
        elif op == "d" and 0 <= idx < len(run.sets):
            run.sets.pop(idx)
        elif op == "u" and 0 < idx < len(run.sets):
            run.sets[idx - 1], run.sets[idx] = run.sets[idx], run.sets[idx - 1]
        elif op == "b":
            if arg.isdigit() and 1 <= int(arg) <= MAX_BUDGET:
                run.failure_budget = int(arg)
            else:
                print(f"   Refused: the failure budget must be 1 to {MAX_BUDGET}.")
        else:
            print("   Not understood.")


# ---------------------------------------------------------------- variant C: passwords only


def variant_c(run: RunStart, session: Session) -> None:
    sets = session.cli_sets or [("netops-ro", []), ("svc-nexus", ["NX-OS"])]
    source = "--set flags" if session.cli_sets else "demo --set flags (pass your own with --set user[:ios|:nxos])"
    print(f"Step 3 - Credential Sets from {source}")
    for username, platforms in sets[:MAX_SETS]:
        limit = ", ".join(platforms) + " only" if platforms else "any Platform"
        pw = ask_device_password(f"{username} ({limit})", run, session.mask)
        run.sets.append(CredentialSet(username, pw, platforms))
        show_state(run, f"password for {username} entered")


# ---------------------------------------------------------------- variant D: Credential Manager (simulated)


def variant_d(run: RunStart, session: Session) -> None:
    print("Step 3 - Credential Sets from Windows Credential Manager (SIMULATED)")
    print("   Looking for generic credentials named NetworkAnalyser/1 ... NetworkAnalyser/5")
    print("   that you created yourself with:  cmdkey /generic:NetworkAnalyser/1 /user:netops-ro /pass")
    fake = [("NetworkAnalyser/1", "netops-ro", []), ("NetworkAnalyser/2", "svc-nexus", ["NX-OS"])]
    for target, username, platforms in fake:
        # A real read would return the stored password here; the prototype invents one.
        run.sets.append(CredentialSet(username, f"simulated-{target}", platforms))
        print(f"   found {target}: {username}")
    print("   Platform limits would need a naming convention, e.g. NetworkAnalyser/2:nxos.")
    print()
    print("   CAUTION: Windows protects these entries with DPAPI, which lets ANY program")
    print("   running as you read them back silently. CLAUDE.md would need a recorded")
    print("   exception to 'passwords are never stored'.")
    show_state(run, "2 sets read from Credential Manager (simulated), nothing typed")


VARIANTS = {
    "A": ("Step by step", variant_a),
    "B": ("Review screen", variant_b),
    "C": ("Passwords only (usernames from --set)", variant_c),
    "D": ("Credential Manager (simulated)", variant_d),
}


# ---------------------------------------------------------------- launcher


def run_variant(key: str, session: Session) -> None:
    name, flow = VARIANTS[key]
    run = RunStart(variant=key, failure_budget=session.failure_budget)
    kind = "first Run" if session.check_passphrase is None else "returning Run"
    print("\n" + "=" * 68)
    print(f" Network Analyser - Run start   [prototype flow {key}: {name}; {kind}]")
    print("=" * 68)
    started = time.monotonic()
    try:
        crash_dump_step(run, session)
        passphrase_step(run, session)
        flow(run, session)
        confirm_start(run, started)
    except StopRun as stop:
        print(f"\n   RUN STOPPED: {stop}")
    except KeyboardInterrupt:
        print("\n\n   Run cancelled (Ctrl+C). Nothing was saved.")
    finally:
        # Dropping the references; a real tool cannot reliably wipe Python memory either.
        run.passphrase = None
        for s in run.sets:
            s.password = ""


def parse_cli_set(value: str) -> tuple[str, list[str]]:
    username, _, codes = value.partition(":")
    platforms = []
    for code in filter(None, codes.lower().split(",")):
        if code not in PLATFORM_CODES:
            raise argparse.ArgumentTypeError(f"unknown Platform '{code}' (use ios or nxos)")
        platforms.append(PLATFORM_CODES[code])
    return username, sorted(set(platforms))


def main() -> None:
    parser = argparse.ArgumentParser(description="PROTOTYPE: Credential Set prompt flows")
    parser.add_argument("--variant", choices=list(VARIANTS), help="start straight into one flow")
    parser.add_argument("--set", dest="sets", action="append", type=parse_cli_set, default=[],
                        metavar="USER[:ios|:nxos]", help="Credential Set username for flow C (repeatable, max 5)")
    parser.add_argument("--failure-budget", type=int, default=3)
    parser.add_argument("--mask", action="store_true", help="show * for each hidden character")
    parser.add_argument("--dump-risk", action="store_true", help="simulate Windows set to keep crash dumps")
    args = parser.parse_args()
    if not 1 <= args.failure_budget <= MAX_BUDGET:
        parser.error(f"--failure-budget must be 1 to {MAX_BUDGET}")
    if len(args.sets) > MAX_SETS:
        parser.error(f"at most {MAX_SETS} --set flags")

    session = Session(mask=args.mask, dump_risk=args.dump_risk,
                      failure_budget=args.failure_budget, cli_sets=args.sets)
    if args.variant:
        run_variant(args.variant, session)
    while True:
        print("\n--- PROTOTYPE launcher (nothing is saved; quitting forgets the passphrase) ---")
        for key, (name, _) in VARIANTS.items():
            print(f"   {key}  {name}")
        print(f"   m  masking with * is {'ON' if session.mask else 'OFF'}   "
              f"x  crash-dump risk is {'ON' if session.dump_risk else 'OFF'}   q  quit")
        try:
            choice = ask("   Pick: ").upper()
        except (KeyboardInterrupt, EOFError):
            print()
            return
        if choice == "Q":
            return
        if choice == "M":
            session.mask = not session.mask
        elif choice == "X":
            session.dump_risk = not session.dump_risk
        elif choice in VARIANTS:
            run_variant(choice, session)


if __name__ == "__main__":
    main()
