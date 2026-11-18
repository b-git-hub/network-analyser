#!/usr/bin/env python3
"""PROTOTYPE - throwaway. Never merge to main.

Question ("How the operator starts and follows a Run", issue 31):
what does using Network Analyser look like at the console, from typing the
command to the final summary?

The launcher offers numbered tours (each plays one case end to end), and
a custom menu that mixes:
  - how the Run is started: 1 flags, 2 run file, 3 asked at the prompt
  - how progress is shown:  A log lines, B live panel, C quiet
  - the scenario:           normal, partial failures, stopped with Ctrl+C
Press Ctrl+C yourself during any Run: once stops gracefully, twice closes
the sessions at once.

Everything is simulated. Nothing touches the network, the disk, the
registry or Credential Manager. No real password is asked for: the secret
prompts settled on "How the operator enters Credential Sets at Run start"
(issue 15) are played back with fake input. Standard library only.

    py prototypes\\run-console\\run_console_prototype.py
"""

import ipaddress
import os
import random
import re
import shutil
import signal
import sys
import textwrap
import time
from collections import deque

VERSION = "0.1.0"
PS = r"PS C:\work> "
RUNS_PARENT = r"C:\Users\operator\AppData\Local\NetworkAnalyser\runs"
DEMO_SCOPE = ["10.10.0.0/16", "10.20.0.0-10.20.0.255"]
DEMO_EXCLUDE = ["10.10.99.0/24"]
DEMO_SEEDS = ["10.10.0.1", "10.10.0.2"]
DEMO_LABEL = "dc1-core"
SUPPORTED = ("IOS-XE", "NX-OS")
PLATFORM_NAME = {"IOS-XE": "IOS/IOS-XE", "NX-OS": "NX-OS", None: "any Platform"}

# Unvisited reasons (fixed list from "Discovery and crawl" + "Topology model").
NEEDS_ATTENTION = {
    "unreachable",
    "SSH algorithms too old",
    "host key changed",
    "host key not yet trusted (strict mode)",
    "authentication failed (every eligible set tried)",
    "not attempted (Credential Sets retired)",
}
STOPPED = "not attempted (Run stopped)"

# Untrusted device text is never printed raw ("Testing against recorded
# device output": strip terminal escapes).
_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def safe(text):
    return _CTRL.sub(lambda m: "\\x%02x" % ord(m.group()), text)


def clock(t):
    t = int(t)
    return f"{t // 3600:02d}:{t % 3600 // 60:02d}:{t % 60:02d}"


def fit(text, width):
    return text if len(text) <= width else text[: max(0, width - 1)] + "~"


def term_width():
    return max(60, min(120, shutil.get_terminal_size((100, 30)).columns))


# --------------------------------------------------------------------------
# Scope parsing (strict, IPv4 only), as decided on "Discovery and crawl".
# --------------------------------------------------------------------------

class ScopeError(ValueError):
    pass


def parse_entry(text):
    raw = text.strip()
    try:
        if "-" in raw:
            a, b = (ipaddress.IPv4Address(x.strip()) for x in raw.split("-", 1))
            if b < a:
                raise ScopeError(f"{raw}: the range is reversed")
            return list(ipaddress.summarize_address_range(a, b))
        if "/" in raw:
            try:
                return [ipaddress.IPv4Network(raw, strict=True)]
            except ValueError as e:
                if "host bits" in str(e):
                    fixed = ipaddress.IPv4Network(raw, strict=False)
                    raise ScopeError(f"{raw}: host bits are set (did you mean {fixed}?)")
                raise
        return [ipaddress.IPv4Network(ipaddress.IPv4Address(raw))]
    except ScopeError:
        raise
    except ValueError:
        if re.search(r"[a-zA-Z]", raw) and ":" not in raw:
            raise ScopeError(f"{raw}: not an IPv4 address (hostnames are refused)")
        if ":" in raw:
            raise ScopeError(f"{raw}: IPv6 is not supported in v1")
        raise ScopeError(f"{raw}: not an IPv4 address, range or CIDR")


class Scope:
    def __init__(self, includes, excludes):
        inc, exc, self.warnings = [], [], []
        for e in includes:
            inc += parse_entry(e)
        for e in excludes:
            exc += parse_entry(e)
        if not inc:
            raise ScopeError("the Scope is empty")
        self.raw_includes, self.raw_excludes = includes, excludes
        self.includes = list(ipaddress.collapse_addresses(inc))
        self.excludes = list(ipaddress.collapse_addresses(exc))
        if sum(n.num_addresses for n in self.includes) < sum(n.num_addresses for n in inc):
            self.warnings.append("overlapping Scope entries were merged")
        for x in self.excludes:
            if not any(x.overlaps(i) for i in self.includes):
                raise ScopeError(f"exclusion {x} matches nothing in the Scope")

    def where(self, ip):
        a = ipaddress.IPv4Address(ip)
        if any(a in x for x in self.excludes):
            return "excluded"
        if any(a in i for i in self.includes):
            return "in"
        return "outside"

    def count(self):
        total = sum(n.num_addresses for n in self.includes)
        for x in self.excludes:
            for i in self.includes:
                if x.subnet_of(i):
                    total -= x.num_addresses
                elif i.subnet_of(x):
                    total -= i.num_addresses
        return total


# --------------------------------------------------------------------------
# The simulated network (synthetic: documentation and RFC 1918 addresses).
# --------------------------------------------------------------------------

class Dev:
    def __init__(self, ip, name, plat, model, advertised=None):
        self.ip, self.name, self.plat, self.model = ip, name, plat, model
        self.advertised = advertised or model
        self.nbrs = []
        self.fail = None


def build_network(partial):
    net = {}

    def add(ip, name, plat, model, advertised=None):
        net[ip] = Dev(ip, name, plat, model, advertised)
        return ip

    def link(a, b):
        net[a].nbrs.append(b)
        net[b].nbrs.append(a)

    core = [add("10.10.0.1", "core-1", "IOS-XE", "C9500-48Y4C"),
            add("10.10.0.2", "core-2", "IOS-XE", "C9500-48Y4C")]
    dist = [add(f"10.10.0.1{i}", f"dist-{i}", "IOS-XE", "C9300-48UXM") for i in range(1, 5)]
    wan = [add("10.10.0.21", "wan-1", "IOS-XE", "C8300-1N1S-6T"),
           add("10.10.0.22", "wan-2", "IOS-XE", "C8300-1N1S-6T")]
    dc = [add(f"10.20.0.{i}", f"dc-leaf-{i}", "NX-OS", "N9K-C93180YC-FX") for i in range(1, 5)]
    fw = add("10.10.0.254", "fw-edge-1", "PAN-OS", "PA-3420", "Palo Alto Networks PA-3420")
    isp = [add("203.0.113.1", "isp-rtr-1", "IOS-XE", "ISR4451-X"),
           add("198.51.100.1", "isp-rtr-2", "IOS-XE", "ISR4451-X")]
    lab = add("10.10.99.5", "lab-sw-1", "IOS-XE", "C9200L-24T-4G")

    link(core[0], core[1])
    for c in core:
        for d in dist:
            link(c, d)
        link(c, fw)
    link(core[0], wan[0]); link(core[1], wan[1])
    link(wan[0], isp[0]); link(wan[1], isp[1])
    link(core[0], dc[0]); link(core[0], dc[1]); link(core[1], dc[2]); link(core[1], dc[3])
    link(dc[0], dc[1]); link(dc[2], dc[3])
    for d in range(1, 5):
        for j in range(1, 7):
            a = add(f"10.10.{d}.1{j}", f"acc-{d}-{j}", "IOS-XE", "C9200L-48P-4X")
            link(dist[d - 1], a)
            if j == 2:
                p = add(f"10.10.{d}.20{j}", f"SEP0000000{d}00{j}", "phone", "CP-8851",
                        "Cisco IP Phone 8851")
                link(a, p)
            if j == 5:
                p = add(f"10.10.{d}.21{j}", f"ap-{d}-{j}", "AP", "C9130AXI",
                        "Cisco AP C9130AXI (lightweight)")
                link(a, p)
    link("10.10.3.16", lab)

    if partial:
        net["10.10.1.13"].fail = "key-changed"
        net["10.10.2.15"].fail = "algos"
        net["10.10.3.12"].fail = "unreachable"
        net["10.10.4.13"].fail = "cmd-timeout"
        net["10.10.4.16"].fail = "priv-low"
        net["10.10.1.16"].name = "acc-1-6\x1b[2J\x07"  # hostile hostname, shown escaped
    return net


# --------------------------------------------------------------------------
# The simulated Run.
# --------------------------------------------------------------------------

class CredSet:
    def __init__(self, n, user, limit, good=True):
        self.n, self.user, self.limit, self.good = n, user, limit, good
        self.ok = self.fail = 0
        self.retired = False

    def state(self):
        if self.retired:
            return "RETIRED"
        if self.ok == 0 and self.fail == 0:
            return "not used yet"
        return f"{self.ok} ok, {self.fail} failed"


class Job:
    def __init__(self, dev, cs, t):
        self.dev, self.cs = dev, cs
        self.label, self.left, self.stage_t0 = "", 0.0, t
        self.login_done = False
        self.identified = False
        self.partial = None
        self.no_backup = None
        self.gen = None


class Problem:
    def __init__(self, ip, name, what, hint=""):
        self.ip, self.name, self.what, self.hint = ip, name, what, hint


class Run:
    TICK = 0.25  # simulated seconds per step

    def __init__(self, cfg, scope, seeds, sets, view):
        self.cfg, self.scope, self.sets, self.view = cfg, scope, sets, view
        self.net = build_network(cfg["scenario"] == "partial")
        self.parallel = cfg["parallel"]
        self.budget = cfg["budget"]
        self.t = 0.0
        self.rng = random.Random(7)
        self.queue = []
        self.known = set()
        self.inflight = {}
        self.visited = {}     # ip -> (dev, job)
        self.unvisited = {}   # ip -> (name, reason)
        self.problems = []
        self.new_keys = 0
        self.lock_queue = deque()
        self.lock_left = None
        self.locked = 0
        self.interrupts = 0
        self.stopping = 0
        self.auto_stopped = False
        for ip in seeds:
            if ip not in self.net:
                self.net[ip] = Dev(ip, "?", "IOS-XE", "?")
                self.net[ip].fail = "unreachable"
            self.known.add(ip)
            self.queue.append(self.net[ip])

    # ---- bookkeeping ------------------------------------------------------

    def event(self, level, dev, text):
        self.view.event(self, level, dev, text)

    def unvisit(self, dev, reason, detail="", hint="", quiet=False):
        self.unvisited[dev.ip] = (dev.name if dev.name != "?" else "", reason)
        if quiet:
            return
        if reason in NEEDS_ATTENTION:
            self.problems.append(Problem(dev.ip, dev.name, reason + (f": {detail}" if detail else ""), hint))
            self.event("attention", dev, reason + (f" ({detail})" if detail else ""))
        elif reason == STOPPED:
            self.event("info", dev, reason)
        else:
            self.event("expected", dev, f"Unvisited: {reason}" + (f" ({detail})" if detail else ""))

    def eligible_sets(self, dev):
        sets = [s for s in self.sets if not s.retired and (s.limit is None or s.limit == dev.plat)]
        return sorted(sets, key=lambda s: (s.ok == 0, s.n))

    def on_probation_busy(self, cs):
        return cs.ok == 0 and any(j.cs is cs and not j.login_done for j in self.inflight.values())

    def set_failed(self, cs):
        cs.fail += 1
        if cs.fail >= self.budget and not cs.retired:
            cs.retired = True
            self.event("notice", None,
                       f"Credential Set {cs.n} ({cs.user}) RETIRED after {cs.fail} failed logins: "
                       f"it is not tried again this Run. A mistyped password is the usual cause.")
            for d in list(self.queue):
                if not self.eligible_sets(d):
                    self.queue.remove(d)
                    self.unvisit(d, "not attempted (Credential Sets retired)")
            self.problems.append(Problem("", f"Set {cs.n}", f"Credential Set {cs.user} retired",
                                         f"It failed {cs.fail} logins in a row. Check its password and "
                                         "account, and your AAA server's lockout counter, before the next Run."))

    def learn(self, nb):
        if nb.ip in self.known:
            return 0
        self.known.add(nb.ip)
        where = self.scope.where(nb.ip)
        if where == "excluded":
            self.unvisit(nb, "excluded by operator")
        elif where == "outside":
            self.unvisit(nb, "outside Scope")
        elif nb.plat not in SUPPORTED:
            self.unvisit(nb, "unsupported Platform (advertised)", safe(nb.advertised))
        elif self.stopping:
            self.unvisit(nb, STOPPED, quiet=True)
        elif not self.eligible_sets(nb):
            self.unvisit(nb, "not attempted (Credential Sets retired)")
        else:
            self.queue.append(nb)
            return 1
        return 0

    # ---- one device -------------------------------------------------------

    def flow(self, dev, job):
        r = self.rng
        if dev.fail == "unreachable":
            yield "connecting", 10
            self.event("info", dev, "no answer on TCP 22 after 10 s; one retry in 30 s")
            yield "waiting to retry", 30
            yield "connecting (retry)", 10
            job.login_done = True
            self.unvisit(dev, "unreachable", "no answer on TCP 22, retried once",
                         "Check the device is up and that SSH is reachable from this PC.")
            return
        yield "connecting", r.uniform(0.5, 1.5)
        if dev.fail == "algos":
            job.login_done = True
            self.unvisit(dev, "SSH algorithms too old", "offers only SHA-1 key exchange",
                         "Enable modern SSH key exchange on the device; v1 has no legacy switch.")
            return
        yield "checking host key", 0.3
        if dev.fail == "key-changed":
            job.login_done = True
            self.unvisit(dev, "host key changed", "no password was sent",
                         "Check the new key on the device's console, then run:\n"
                         f"network-analyser trust-key {dev.ip} --fingerprint SHA256:<new key from the report>")
            return
        cs = job.cs
        while True:
            yield f"logging in as {cs.user}", r.uniform(1.0, 2.5)
            if cs.good:
                cs.ok += 1
                break
            rest = [s for s in self.eligible_sets(dev) if s is not cs and s.n > cs.n]
            if not rest:
                job.login_done = True
                users = ", ".join(s.user for s in self.sets if s.limit in (None, dev.plat))
                self.unvisit(dev, "authentication failed (every eligible set tried)",
                             f"tried {users}")
                self.set_failed(cs)
                return
            self.set_failed(cs)
            cs = job.cs = rest[0]
        job.login_done = True
        self.new_keys += 1
        yield "identifying", r.uniform(1.0, 2.0)
        job.identified = True
        self.event("info", dev, f"logged in as {cs.user}: {dev.plat} {dev.model}")
        if dev.fail == "cmd-timeout":
            yield "collecting", r.uniform(8, 15)
            yield "waiting: show lldp neighbors detail", 60
            job.partial = "show lldp neighbors detail timed out after 60 s"
            self.event("attention", dev, "partial: " + job.partial)
            yield "collecting", r.uniform(8, 15)
        else:
            yield "collecting", r.uniform(18, 40)
        new = 0
        if job.partial is None:
            for ip in dev.nbrs:
                new += self.learn(self.net[ip])
        else:
            for ip in dev.nbrs[:1]:
                new += self.learn(self.net[ip])
        job.new_nbrs = new
        if dev.fail == "priv-low":
            yield "taking Backup", 1.5
            job.no_backup = "landed at privilege 1; show running-config was refused"
        else:
            yield "taking Backup", r.uniform(5, 12)
            self.lock_queue.append(dev)
        self.finish_visit(dev, job)

    def finish_visit(self, dev, job):
        self.visited[dev.ip] = (dev, job)
        n = len(dev.nbrs)
        bits = [f"{dev.plat} {dev.model}", f"{n} Neighbour{'s' if n != 1 else ''} ({getattr(job, 'new_nbrs', 0)} new)"]
        if job.no_backup:
            self.problems.append(Problem(dev.ip, dev.name, "Backup not taken: " + job.no_backup,
                                         "Give the account the Device Role: network-analyser role-snippet ios-xe"))
            self.event("attention", dev, "Visited, but Backup not taken: " + job.no_backup)
            return
        if job.partial:
            self.problems.append(Problem(dev.ip, dev.name, "partial: " + job.partial,
                                         "Its Neighbours may be missing from the Topology."))
            self.event("info", dev, "Visited (partial, see above); Backup captured")
            return
        self.event("ok", dev, "; ".join(bits) + "; Backup captured")

    # ---- the loop ---------------------------------------------------------

    def dispatch(self):
        if self.stopping:
            return
        i = 0
        while len(self.inflight) < self.parallel and i < len(self.queue):
            dev = self.queue[i]
            sets = self.eligible_sets(dev)
            if not sets:
                del self.queue[i]
                self.unvisit(dev, "not attempted (Credential Sets retired)")
                continue
            if self.on_probation_busy(sets[0]):
                i += 1
                continue
            del self.queue[i]
            job = Job(dev, sets[0], self.t)
            job.gen = self.flow(dev, job)
            self.inflight[dev.ip] = job
            self.advance(job, 0.0)

    def advance(self, job, dt):
        job.left -= dt
        while job.left <= 0:
            try:
                label, dur = next(job.gen)
            except StopIteration:
                self.inflight.pop(job.dev.ip, None)
                return
            job.label, job.left, job.stage_t0 = label, job.left + dur, self.t

    def lock_step(self, dt):
        if self.lock_left is not None:
            self.lock_left -= dt
            if self.lock_left <= 0:
                self.locked += 1
                self.lock_left = None
        if self.lock_left is None and self.lock_queue:
            self.lock_queue.popleft()
            self.lock_left = 1.5

    def stop_gracefully(self):
        self.stopping = 1
        n = len(self.inflight)
        self.view.notice(self, f"Stopping: no new logins will start. Waiting for {n} session"
                               f"{'s' if n != 1 else ''} in progress to finish (each ends within its "
                               f"timeouts). Press Ctrl+C again to close them now.")
        for d in list(self.queue):
            self.unvisit(d, STOPPED, quiet=True)
        if self.queue:
            self.event("info", None, f"{len(self.queue)} queued devices recorded as '{STOPPED}'")
        self.queue.clear()

    def stop_now(self):
        self.stopping = 2
        n = len(self.inflight)
        self.view.notice(self, f"Closing {n} session{'s' if n != 1 else ''} now. "
                               f"No partial Backup is written. Backups already captured are still locked.")
        for job in list(self.inflight.values()):
            job.gen.close()
            if job.identified:
                job.no_backup = None
                job.partial = "session closed by the operator before it finished"
                self.visited[job.dev.ip] = (job.dev, job)
            else:
                self.unvisit(job.dev, STOPPED)
        self.inflight.clear()

    def done(self):
        return not self.queue and not self.inflight and not self.lock_queue and self.lock_left is None

    def go(self):
        speed = self.cfg["speed"]
        old = signal.getsignal(signal.SIGINT)

        def on_ctrl_c(signum, frame):
            self.interrupts += 1
        signal.signal(signal.SIGINT, on_ctrl_c)
        try:
            self.view.start(self)
            while True:
                if self.cfg["scenario"] == "stopped" and not self.auto_stopped and self.t >= 75:
                    self.auto_stopped = True
                    self.interrupts += 1
                    self.view.echo_ctrl_c(self)
                if self.interrupts >= 1 and self.stopping == 0:
                    if not self.auto_stopped:
                        self.view.echo_ctrl_c(self)
                    self.stop_gracefully()
                if self.interrupts >= 2 and self.stopping == 1:
                    self.view.echo_ctrl_c(self)
                    self.stop_now()
                self.dispatch()
                for job in list(self.inflight.values()):
                    self.advance(job, self.TICK)
                self.lock_step(self.TICK)
                self.view.tick(self)
                if self.done():
                    break
                self.t += self.TICK
                time.sleep(self.TICK / speed)
            self.view.finish(self)
        finally:
            signal.signal(signal.SIGINT, old)


# --------------------------------------------------------------------------
# Progress views.
# --------------------------------------------------------------------------

def counts(run):
    need = sum(1 for _, r in run.unvisited.values() if r in NEEDS_ATTENTION)
    return dict(v=len(run.visited), i=len(run.inflight), q=len(run.queue), u=len(run.unvisited),
                need=need, b=run.locked, w=len(run.lock_queue) + (run.lock_left is not None))


class LogView:
    """A: one line per event, scrolling. Works the same when redirected to a file."""
    name = "Log lines"
    SYM = {"ok": "OK", "info": "  ", "expected": "--", "attention": "!!", "notice": "**"}

    def __init__(self):
        self.next_status = 60

    def start(self, run):
        print("Elapsed    .. IP              Hostname      What happened")

    def line(self, run, sym, ip, name, text):
        w = term_width()
        if sym == "**":
            parts = textwrap.wrap(text, w - 15)
            print(f"[{clock(run.t)}] ** {parts[0]}")
            for more in parts[1:]:
                print(f"{'':14}{more}")
            return
        print(fit(f"[{clock(run.t)}] {sym} {ip:<15} {fit(name, 12):<12}  {text}", w - 1))

    def event(self, run, level, dev, text):
        if dev is None:
            self.line(run, self.SYM[level], "", "", text)
        else:
            self.line(run, self.SYM[level], dev.ip, safe(dev.name), text)

    def notice(self, run, text):
        self.line(run, "**", "", "", text)

    def echo_ctrl_c(self, run):
        print("^C")

    def tick(self, run):
        if run.t >= self.next_status:
            self.next_status += 60
            c = counts(run)
            self.line(run, "..", "", "", f"status: {c['v']} Visited, {c['i']} in progress, {c['q']} queued, "
                                         f"{c['u']} Unvisited ({c['need']} need attention), "
                                         f"{c['b']} Backups locked")

    def finish(self, run):
        pass


class LiveView:
    """B: a fixed panel redrawn in place, like a dashboard."""
    name = "Live panel"

    def __init__(self):
        self.drawn = 0
        self.last = 0.0
        self.recent = deque(maxlen=4)
        self.banner = ""

    def start(self, run):
        if os.name == "nt":
            os.system("")  # turns on VT escape handling in the classic console host

    def event(self, run, level, dev, text):
        if level == "attention":
            self.recent.append(f"!! {dev.ip:<15} {fit(safe(dev.name), 12):<12} {text}")
        elif level == "notice":
            self.banner = text

    def notice(self, run, text):
        self.banner = text
        self.draw(run, force=True)

    def echo_ctrl_c(self, run):
        pass

    def tick(self, run):
        self.draw(run)

    def draw(self, run, force=False):
        now = time.monotonic()
        if not force and now - self.last < 0.2:
            return
        self.last = now
        w = term_width() - 1
        c = counts(run)
        sets = "   ".join(f"{s.n} {s.user}: {s.state()}" for s in run.sets)
        rows = min(run.parallel, 10)
        lines = [
            f" Network Analyser   Run {run.cfg['folder']}",
            " " + "-" * (w - 2),
            f" Elapsed {clock(run.t)}    Visited {c['v']:<4} In progress {c['i']}/{run.parallel:<4}"
            f" Queued {c['q']:<4} Unvisited {c['u']} ({c['need']} need attention)",
            f" Backups locked {c['b']}, waiting {c['w']}    Credential Sets  {sets}",
            "",
            " In progress",
        ]
        jobs = sorted(run.inflight.values(), key=lambda j: j.stage_t0)
        for k in range(rows):
            if k < len(jobs):
                j = jobs[k]
                lines.append(f"   {j.dev.ip:<15} {fit(safe(j.dev.name), 12):<12} {fit(j.label, 36):<36}"
                             f" {clock(run.t - j.stage_t0)[3:]}")
            else:
                lines.append("")
        lines += ["", " Needs attention (latest 4; all are listed at the end)"]
        rec = list(self.recent)
        lines += [f"   {rec[k]}" if k < len(rec) else "" for k in range(4)]
        ban = textwrap.wrap(self.banner, w - 4) if self.banner else []
        ban = (ban + ["", ""])[:2]
        lines += ["", f" ** {ban[0]}" if ban[0] else "", f"    {ban[1]}" if ban[1] else "",
                  " Ctrl+C stops the Run (outputs are still written)." if not run.stopping
                  else " Ctrl+C again closes the sessions now." if run.stopping == 1 else ""]
        out = []
        if self.drawn:
            out.append(f"\x1b[{self.drawn}F")
        for ln in lines:
            out.append("\x1b[2K" + fit(ln, w) + "\n")
        sys.stdout.write("".join(out))
        sys.stdout.flush()
        self.drawn = len(lines)

    def finish(self, run):
        self.draw(run, force=True)


class QuietView:
    """C: one status line updated in place; only problems and notices are printed."""
    name = "Quiet"

    def __init__(self):
        self.last = 0.0
        self.status_len = 0

    def clear(self):
        sys.stdout.write("\r" + " " * self.status_len + "\r")

    def start(self, run):
        print("Only problems are printed. Everything is in the run report and audit.log.")

    def event(self, run, level, dev, text):
        if level not in ("attention", "notice"):
            return
        self.clear()
        if dev is None:
            print(fit(f"** {text}", term_width() - 1))
        else:
            print(fit(f"!! {dev.ip:<15} {fit(safe(dev.name), 12):<12} {text}", term_width() - 1))
        self.status(run)

    def notice(self, run, text):
        self.clear()
        print(f"** {text}")
        self.status(run)

    def echo_ctrl_c(self, run):
        self.clear()
        print("^C")

    def status(self, run):
        c = counts(run)
        s = (f"[{clock(run.t)}] Visited {c['v']}  In progress {c['i']}  Queued {c['q']}  "
             f"Unvisited {c['u']}  Backups {c['b']}")
        s = fit(s, term_width() - 1)
        sys.stdout.write("\r" + s.ljust(self.status_len))
        sys.stdout.flush()
        self.status_len = len(s)

    def tick(self, run):
        now = time.monotonic()
        if now - self.last >= 0.2:
            self.last = now
            self.status(run)

    def finish(self, run):
        self.status(run)
        print()


VIEWS = {"a": LogView, "b": LiveView, "c": QuietView}


# --------------------------------------------------------------------------
# Before the Run: command, Scope, Seeds, secrets (played back), confirm.
# --------------------------------------------------------------------------

def pause(cfg, s):
    if not cfg["brisk"]:
        time.sleep(s)


def typed(cfg, prompt, answer, mask=False):
    print(prompt, end="", flush=True)
    for ch in answer:
        print("*" if mask else ch, end="", flush=True)
        pause(cfg, 0.02)
    print()
    pause(cfg, 0.15)


def ask(prompt):
    try:
        return input(prompt)
    except EOFError:
        raise KeyboardInterrupt


def show_command(cfg):
    scope = DEMO_SCOPE if not cfg["mistake"] else ["10.10.0.1/16", "10.20.0.0-10.20.0.255"]
    if cfg["start"] == "1":
        parts = ["network-analyser run"] + [f"--scope {s}" for s in scope]
        parts += [f"--exclude {x}" for x in DEMO_EXCLUDE]
        if not cfg["no_seeds"]:
            parts += [f"--seed {s}" for s in DEMO_SEEDS]
        parts += [f"--label {DEMO_LABEL}"]
        print(PS + " ".join(parts))
        return scope, DEMO_EXCLUDE, (None if cfg["no_seeds"] else DEMO_SEEDS), "command line"
    if cfg["start"] == "2":
        print(PS + "Get-Content dc1-core.toml")
        print("# Network Analyser run file. Holds no secrets: a password or passphrase key is refused.")
        print(f'label   = "{DEMO_LABEL}"')
        print("scope   = [" + ", ".join(f'"{s}"' for s in scope) + "]")
        print("exclude = [" + ", ".join(f'"{s}"' for s in DEMO_EXCLUDE) + "]")
        if not cfg["no_seeds"]:
            print("seeds   = [" + ", ".join(f'"{s}"' for s in DEMO_SEEDS) + "]")
        print("parallel = 10")
        print("failure_budget = 3")
        print("sweep   = false")
        print()
        print(PS + "network-analyser run --from dc1-core.toml")
        return scope, DEMO_EXCLUDE, (None if cfg["no_seeds"] else DEMO_SEEDS), "dc1-core.toml"
    print(PS + "network-analyser run")
    return None, None, None, "asked"


def ask_scope():
    print("No Scope given. Enter the IPv4 ranges this Run may touch, one per line:")
    print("  CIDR (10.10.0.0/16), range (10.20.0.0-10.20.0.255) or one IP.")
    print("  Start a line with ! to exclude it (!10.10.99.0/24). Empty line when done.")
    print("  [prototype: an empty first line uses the demo Scope]")
    inc, exc = [], []
    while True:
        line = ask("Scope> ").strip()
        if not line:
            if not inc and not exc:
                print("  using " + ", ".join(DEMO_SCOPE) + ", excluding " + ", ".join(DEMO_EXCLUDE))
                return DEMO_SCOPE, DEMO_EXCLUDE
            if not inc:
                print("  At least one range is needed.")
                continue
            try:
                Scope(inc, exc)
                return inc, exc
            except ScopeError as e:
                bad = [x for x in exc if not any(n.overlaps(i) for n in parse_entry(x)
                                                 for e2 in inc for i in parse_entry(e2))]
                exc = [x for x in exc if x not in bad]
                print(f"  Refused: {e}. Dropped !{', !'.join(bad)}; add more lines or press Enter.")
                continue
        target = exc if line.startswith("!") else inc
        entry = line.lstrip("!").strip()
        try:
            parse_entry(entry)
            target.append(entry)
        except ScopeError as e:
            print(f"  Refused: {e}. Enter that line again.")


def ask_seeds(scope):
    print("No Seeds given. Enter one or more device IPs to start the crawl from,")
    print("separated by spaces or commas. Each must be inside the Scope.")
    print("  [prototype: empty uses the demo Seeds 10.10.0.1 10.10.0.2]")
    while True:
        line = ask("Seeds> ").strip()
        if not line:
            return DEMO_SEEDS
        seeds, bad = [], None
        for s in re.split(r"[,\s]+", line):
            try:
                ipaddress.IPv4Address(s)
            except ValueError:
                bad = f"{s} is not an IPv4 address"
                break
            w = scope.where(s)
            if w != "in":
                bad = f"{s} is {'excluded from' if w == 'excluded' else 'outside'} the Scope"
                break
            seeds.append(s)
        if bad:
            print(f"  Refused: {bad}. Enter the Seeds again.")
            continue
        return seeds


def describe_scope(scope):
    lines = [f"Scope       {scope.count():,} addresses in {len(scope.includes)} range"
             f"{'s' if len(scope.includes) != 1 else ''}"]
    for n in scope.includes:
        lines.append(f"              {n}")
    for x in scope.excludes:
        lines.append(f"            excluding {x}")
    for wmsg in scope.warnings:
        lines.append(f"            warning: {wmsg}")
    return lines


def secret_prompts(cfg, sets):
    print()
    print("Checking crash-dump settings (read only) ... no crash dump of this process will be kept.")
    pause(cfg, 0.3)
    typed(cfg, "Backup Passphrase: ", "x" * 22, mask=True)
    print("Backup Passphrase accepted (it unlocked the check file).")
    pause(cfg, 0.3)
    print()
    print("Credential Sets: up to 5, tried in the order you give them.")
    for k, s in enumerate(sets):
        typed(cfg, f"Set {s.n} username: ", s.user)
        typed(cfg, f"Password for {s.user}: ", "x" * 14, mask=True)
        print("Limit to a Platform?  1) IOS/IOS-XE  2) NX-OS  Enter) any Platform")
        typed(cfg, "Platform: ", {"IOS-XE": "1", "NX-OS": "2", None: ""}[s.limit])
        typed(cfg, "Add another Credential Set? [y/N]: ", "y" if k < len(sets) - 1 else "n")


def make_sets(cfg):
    return [CredSet(1, "netops-ro", "IOS-XE"),
            CredSet(2, "svc-nexus", "NX-OS", good=cfg["scenario"] != "partial")]


def before_run(cfg):
    """Returns (scope, seeds, sets) or an exit code."""
    print()
    scope_in, excl_in, seeds_in, source = show_command(cfg)
    pause(cfg, 0.4)
    print(f"Network Analyser {VERSION}. Read-only: it never changes a device's configuration.")
    print(f"Runs folder {RUNS_PARENT} (writable)")
    if scope_in is None:
        scope_in, excl_in = ask_scope()
    try:
        scope = Scope(scope_in, excl_in)
    except ScopeError as e:
        print(f"Refused: {e}.")
        print("Nothing was contacted. Fix the Scope and run again.")
        return 2
    if seeds_in is None:
        for ln in describe_scope(scope):
            print(ln)
        seeds_in = ask_seeds(scope)
    else:
        for s in seeds_in:
            if scope.where(s) != "in":
                print(f"Refused: Seed {s} is outside the Scope. Nothing was contacted.")
                return 2
    sets = make_sets(cfg)
    secret_prompts(cfg, sets)
    print()
    print("Ready to start")
    print(f"  Run folder  {RUNS_PARENT}\\{cfg['folder']}")
    for ln in describe_scope(scope):
        print("  " + ln)
    print(f"  Seeds       {', '.join(seeds_in)}")
    for s in sets:
        print(f"  Set {s.n}       {s.user:<12} {PLATFORM_NAME[s.limit]:<14} password held in memory")
    print(f"  Options     parallel {cfg['parallel']}, failure budget {cfg['budget']}, "
          "Sweep off, host keys: trust on first use")
    if source not in ("command line", "asked"):
        print(f"              (Scope, Seeds and options from {source})")
    if cfg.get("auto"):
        typed(cfg, "Start the Run? [Y/n] ", "y")
        ans = "y"
    else:
        ans = ask("Start the Run? [Y/n] ").strip().lower()
    if ans not in ("", "y", "yes"):
        print("Run cancelled. Nothing was contacted and nothing was saved.")
        return 3
    print(f"Run folder created: {RUNS_PARENT}\\{cfg['folder']}")
    print()
    return scope, seeds_in, sets


# --------------------------------------------------------------------------
# After the Run: outputs and the final summary.
# --------------------------------------------------------------------------

def write_outputs(cfg, run):
    print()
    print("Writing outputs ...")
    for what in ("topology.json", "diagram.html, diagram.drawio", "run-report", "audit.log"):
        pause(cfg, 0.25)
        print(f"  {what}")


def summary(cfg, run):
    w = min(term_width() - 1, 100)
    folder = f"{RUNS_PARENT}\\{cfg['folder']}"
    stopped = run.stopping > 0
    vis = list(run.visited.values())
    backups = run.locked
    partial = [d for d, j in vis if j.partial]
    no_bk = [d for d, j in vis if j.no_backup]
    by_reason = {}
    for name, reason in run.unvisited.values():
        by_reason[reason] = by_reason.get(reason, 0) + 1
    attention = {r: n for r, n in by_reason.items() if r in NEEDS_ATTENTION}
    expected = {r: n for r, n in by_reason.items() if r not in NEEDS_ATTENTION and r != STOPPED}

    print("=" * w)
    if stopped:
        print(f"Run STOPPED by Ctrl+C after {clock(run.t)}. Outputs cover what was found before the stop.")
    elif run.problems:
        print(f"Run finished in {clock(run.t)}, with {len(run.problems)} item"
              f"{'s' if len(run.problems) != 1 else ''} that need your attention.")
    else:
        print(f"Run finished in {clock(run.t)}. Nothing needs your attention.")
    print("-" * w)
    print(f"Visited     {len(vis):>3}   Backups locked {backups}"
          + (f", partial {len(partial)}" if partial else "")
          + (f", Backup not taken {len(no_bk)}" if no_bk else ""))
    print(f"Unvisited   {len(run.unvisited):>3}")
    for r, n in sorted(attention.items(), key=lambda x: -x[1]):
        print(f"   !! {n:>3}  {r}")
    if by_reason.get(STOPPED):
        print(f"      {by_reason[STOPPED]:>3}  {STOPPED}")
    for r, n in sorted(expected.items(), key=lambda x: -x[1]):
        print(f"      {n:>3}  {r}")
    print("Credential Sets")
    for s in run.sets:
        tail = (f"RETIRED after {s.fail} failed logins" if s.retired
                else f"{s.fail} failed login{'s' if s.fail != 1 else ''}")
        print(f"   {s.n} {s.user:<12} {PLATFORM_NAME[s.limit]:<12} logged into {s.ok:>2} devices, {tail}")
    print(f"Host keys trusted for the first time: {run.new_keys} (fingerprints are in the run report)")

    if run.problems:
        print("-" * w)
        print("Needs your attention")
        order = sorted(run.problems, key=lambda p: (p.what.split(":")[0],
                                                     ipaddress.IPv4Address(p.ip or "0.0.0.0")))
        for p in order:
            print(fit(f"  {p.ip:<15} {fit(safe(p.name), 12):<12} {p.what}", w))
            for para in p.hint.splitlines():
                wrapped = [para] if para.startswith("network-analyser") else textwrap.wrap(para, w - 33)
                for hl in wrapped or [""]:
                    print(f"  {'':<15} {'':<12}   {hl}")
    print("-" * w)
    print(f"Run folder  {folder}")
    print(f"Diagram     {folder}\\diagram.html")
    print(f"Run report  {folder}\\run-report.<format from 'Run report and audit log'>")
    print("=" * w)
    code = 3 if stopped else (1 if run.problems else 0)
    meaning = {0: "finished, nothing needs attention", 1: "finished, needs attention",
               3: "stopped by the operator"}[code]
    print(f"[prototype] exit code {code} ({meaning})")
    return code


# --------------------------------------------------------------------------
# Proposed help text.
# --------------------------------------------------------------------------

HELP = r"""
PS C:\work> network-analyser --help
usage: network-analyser <command> [options]

Network Analyser 0.1.0: logs into Cisco IOS/IOS-XE and NX-OS devices inside the
IP ranges you give, backs up their running configuration (encrypted), follows
CDP/LLDP to find more devices, and draws the topology. It is read-only: it never
changes a device's configuration.

commands:
  run                 discover, back up and draw a network (prompts for secrets)
  render              redraw the diagram of an earlier Run, in its Run folder
  show-backup         print one Backup to the console (asks for the Backup Passphrase)
  trust-key           trust a device's new SSH host key after you have checked it
  role-snippet        print the Device Role config to give the tool's account
  change-passphrase   re-lock every Backup with a new Backup Passphrase

Run "network-analyser <command> --help" for its options.

exit codes (every command):
  0  finished; nothing needs attention
  1  finished; something needs attention (listed at the end and in the run report)
  2  refused before contacting any device (bad options, Scope or Seeds; folder not
     writable; crash-dump check declined; wrong Backup Passphrase; another Run active)
  3  stopped or cancelled by the operator (Ctrl+C, or "n" at the confirm)
  4  internal error (a short message; never a traceback with values)

PS C:\work> network-analyser run --help
usage: network-analyser run [--from FILE] [--scope RANGE ...] [--exclude RANGE ...]
                            [--seed IP ...] [options]

Secrets are never options: the Backup Passphrase and Credential Set passwords are
always typed at the prompt that follows.

Scope and Seeds:
  --scope RANGE        IPv4 CIDR, a-b range or single IP the Run may touch. Repeat for
                       more. Asked at start if none is given.
  --exclude RANGE      never touch these addresses, even when advertised. Repeatable.
  --seed IP            a device to start the crawl from; must be inside the Scope.
                       Repeatable. Asked at start if none is given.
  --from FILE          read Scope, Seeds and options from a run file (TOML). Options
                       also given on the command line win, and the summary says so.
Discovery:
  --sweep              also probe every Scope address on TCP 22 to find more Seeds
                       (Scope of 65,536 addresses or fewer)
  --sweep-inflight N   probes in flight during a Sweep (default 100, at most 100)
Connections:
  --parallel N         devices worked on at once (default 10, at most 50)
  --failure-budget N   failed logins a Credential Set may spend before it is retired
                       (default 3, 1 to 5)
  --strict-host-keys   log in only where the host key is already trusted
  --known-hosts FILE   extra trusted host keys, OpenSSH format (read, never written)
  --connect-timeout S  default 10      --login-timeout S    default 20
  --command-timeout S  default 60      --backup-timeout S   default 300
  --device-timeout M   default 15 (minutes)
Outputs:
  --runs-dir DIR       parent of the new Run folder
                       (default %LOCALAPPDATA%\NetworkAnalyser\runs)
  --label TEXT         added to the Run folder name (letters, digits, - . _; 32 max)
  --progress VIEW      how progress is shown: <decided by this prototype>

PS C:\work> network-analyser trust-key --help
usage: network-analyser trust-key IP --fingerprint SHA256:...
  Saves the key only if the device presents exactly that fingerprint.

PS C:\work> network-analyser render --help
usage: network-analyser render RUN_FOLDER
  Redraws diagram.html and diagram.drawio from topology.json, in place.

PS C:\work> network-analyser show-backup --help
usage: network-analyser show-backup BACKUP_FILE
  Prints one Backup (.cfg.age) to the console. Nothing is written to disk.

PS C:\work> network-analyser role-snippet --help
usage: network-analyser role-snippet {ios-xe,nx-os} [--username NAME] [--tacacs]
  Prints the Device Role config to paste on a device or AAA server. Never pushes it.

PS C:\work> network-analyser change-passphrase --help
usage: network-analyser change-passphrase [--run-folder DIR ...]
  --run-folder DIR     also re-lock a Run folder that moved since it was registered
"""


# --------------------------------------------------------------------------
# Launcher.
# --------------------------------------------------------------------------

START_NAMES = {"1": "flags on the command line", "2": "run file (--from)", "3": "asked at the prompt"}
SCEN_NAMES = {"normal": "normal", "partial": "partial failures", "stopped": "stopped with Ctrl+C at 1:15"}
SPEEDS = [4, 8, 16, 32]


def base_cfg(**kw):
    cfg = dict(start="1", view="a", scenario="normal", no_seeds=False, brisk=False, mistake=False,
               speed=8, parallel=10, budget=3, folder="20261118T101530Z_dc1-core", auto=False)
    cfg.update(kw)
    return cfg


TOURS = [
    ("Normal Run, shown as log lines (A)", dict(view="a")),
    ("Normal Run, shown as the live panel (B)", dict(view="b")),
    ("Normal Run, shown quietly (C)", dict(view="c")),
    ("Run with problems, live panel (B)", dict(view="b", scenario="partial")),
    ("Run with problems, log lines (A)", dict(view="a", scenario="partial")),
    ("Run with problems, quiet (C)", dict(view="c", scenario="partial")),
    ("Stopped with Ctrl+C at 1:15 (press Ctrl+C again to close sessions at once)",
     dict(view="b", scenario="stopped")),
    ("Started from a run file, with Seeds left out so they are asked for",
     dict(view="a", start="2", no_seeds=True)),
    ("Started with nothing, so Scope and Seeds are asked for (try typos)", dict(view="a", start="3")),
    ("A typo in the Scope on the command line: refused", dict(start="1", mistake=True)),
]


def launcher():
    while True:
        print()
        print("=" * 76)
        print(" PROTOTYPE: How the operator starts and follows a Run   (nothing is real)")
        print("=" * 76)
        print(" Pick a tour. It plays from the typed command to the final summary.")
        print(" Press Ctrl+C during any Run to stop it the way the real tool would.")
        print()
        for k, (name, _) in enumerate(TOURS, 1):
            print(f"  {k:>2}  {name}")
        print()
        print("   h  proposed help text for every command")
        print("   c  custom: mix the settings yourself")
        print("   q  quit")
        try:
            choice = ask("Tour number> ").strip().lower()
        except KeyboardInterrupt:
            print()
            return
        if choice.isdigit() and 1 <= int(choice) <= len(TOURS):
            name, kw = TOURS[int(choice) - 1]
            print(f"\n--- Tour {choice}: {name} ---")
            play(base_cfg(brisk=True, auto=kw.get("start") != "3", **kw))
        elif choice == "h":
            print(HELP)
            try:
                ask("[Enter to go back] ")
            except KeyboardInterrupt:
                pass
        elif choice == "c":
            custom()
        elif choice == "q":
            return


def custom():
    cfg = base_cfg()
    while True:
        print()
        print("=" * 72)
        print(" PROTOTYPE: How the operator starts and follows a Run  (nothing is real)")
        print("=" * 72)
        print(f" Start     1/2/3  {START_NAMES[cfg['start']]}")
        print(f" Progress  A/B/C  {VIEWS[cfg['view']].__doc__.split(':')[0].strip()}  "
              f"({VIEWS[cfg['view']].name})")
        print(f" Scenario  n/p/s  {SCEN_NAMES[cfg['scenario']]}")
        print(f" Toggles   e  Seeds left out of the command/run file: {'on' if cfg['no_seeds'] else 'off'}")
        print(f"           x  a mistake in the Scope (see the refusal): {'on' if cfg['mistake'] else 'off'}")
        print(f"           k  play the secret prompts briskly: {'on' if cfg['brisk'] else 'off'}")
        print(f"           f  speed x{cfg['speed']} (the clock shown is simulated time)")
        print(" Other     r or Enter  start (answer Y or Enter at 'Start the Run?')     q  back to tours")
        try:
            choice = ask("> ").strip().lower()
        except KeyboardInterrupt:
            print()
            return
        if choice in ("1", "2", "3"):
            cfg["start"] = choice
        elif choice in ("a", "b", "c"):
            cfg["view"] = choice
        elif choice in ("n", "p", "s"):
            cfg["scenario"] = {"n": "normal", "p": "partial", "s": "stopped"}[choice]
        elif choice == "e":
            cfg["no_seeds"] = not cfg["no_seeds"]
        elif choice == "x":
            cfg["mistake"] = not cfg["mistake"]
        elif choice == "k":
            cfg["brisk"] = not cfg["brisk"]
        elif choice == "f":
            cfg["speed"] = SPEEDS[(SPEEDS.index(cfg["speed"]) + 1) % len(SPEEDS)]
        elif choice == "q":
            return
        elif choice in ("r", ""):
            play(cfg)


def play(cfg):
    view = VIEWS[cfg["view"]]()
    if cfg["view"] == "b" and not sys.stdout.isatty():
        print("[prototype] output is not a console, so the live panel falls back to log lines")
        view = LogView()
    try:
        got = before_run(cfg)
    except KeyboardInterrupt:
        print("^C")
        print("Run cancelled. Nothing was contacted and nothing was saved.")
        print("[prototype] exit code 3 (stopped or cancelled by the operator)")
        return
    if isinstance(got, int):
        print(f"[prototype] exit code {got}")
        return
    scope, seeds, sets = got
    run = Run(cfg, scope, seeds, sets, view)
    run.go()
    write_outputs(cfg, run)
    summary(cfg, run)
    try:
        ask("[Enter to go back to the launcher] ")
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    launcher()
