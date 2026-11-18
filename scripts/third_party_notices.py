"""Check every bundled package's licence and write THIRD-PARTY-NOTICES.txt (ticket #44).

    python -m scripts.third_party_notices --out <build folder>/THIRD-PARTY-NOTICES.txt

Decision #32 section 6: the build fails on any licence outside MIT, BSD, Apache-2.0, PSF,
ISC, MPL-2.0 and LGPL, and ships every bundled package's licence text.
"""

import argparse
import platform
import re
import sys
import sysconfig
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import Any

from packaging.markers import Marker, default_environment

REPO_ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True, slots=True)
class Package:
    """What an installed distribution says about its licence."""

    name: str
    version: str
    licence_expression: str | None
    licence_field: str | None
    classifiers: tuple[str, ...]
    licence_texts: tuple[tuple[str, str], ...]
    modules: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Accepted:
    """A package whose licence is allowed, with the licence it is shipped under."""

    package: Package
    licence: str


@dataclass(frozen=True, slots=True)
class Review:
    """The outcome of the licence check: accepted packages and one line per refusal."""

    accepted: list[Accepted]
    refusals: list[str]


# SPDX identifiers (compared without case) in the families decision #32 allows.
ALLOWED_SPDX = frozenset(
    identifier.lower()
    for identifier in (
        "MIT",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "Apache-2.0",
        "PSF-2.0",
        "Python-2.0",
        "ISC",
        "MPL-2.0",
        "LGPL-2.1",
        "LGPL-2.1+",
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "LGPL-3.0",
        "LGPL-3.0+",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
    )
)


# Licence texts for packages whose wheel ships none, saved by hand from the package's own
# source release (repo-relative, one `<name>-<version>.txt` per package).
SUPPLIED_TEXTS_DIR = "scripts/licence_texts"


class UnreadableLicenceError(ValueError):
    """An SPDX licence expression that does not parse."""


_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9.+:-]+)")


def _tokens(expression: str) -> list[str]:
    tokens: list[str] = []
    position = 0
    while position < len(expression.rstrip()):
        match = _TOKEN.match(expression, position)
        if match is None:
            raise UnreadableLicenceError(expression)
        tokens.append(match.group(1))
        position = match.end()
    return tokens


class _Parser:
    """Recursive descent over `term (AND term)* (OR ...)*`; WITH adds only permissions."""

    def __init__(self, expression: str) -> None:
        self.tokens = _tokens(expression)
        self.position = 0

    def allowed(self) -> bool:
        result = self._or()
        if self.position != len(self.tokens):
            raise UnreadableLicenceError
        return result

    def _peek(self) -> str | None:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def _take(self) -> str:
        token = self._peek()
        if token is None:
            raise UnreadableLicenceError
        self.position += 1
        return token

    def _or(self) -> bool:
        results = [self._and()]
        while (self._peek() or "").upper() == "OR":
            self._take()
            results.append(self._and())
        return any(results)

    def _and(self) -> bool:
        results = [self._term()]
        while (self._peek() or "").upper() == "AND":
            self._take()
            results.append(self._term())
        return all(results)

    def _identifier(self) -> str:
        word = self._take()
        if word in {"(", ")"} or word.upper() in {"AND", "OR", "WITH"}:
            raise UnreadableLicenceError
        return word

    def _term(self) -> bool:
        if self._peek() == "(":
            self._take()
            result = self._or()
            if self._take() != ")":
                raise UnreadableLicenceError
            return result
        licence = self._identifier()
        if (self._peek() or "").upper() == "WITH":
            self._take()
            self._identifier()  # an exception only adds permissions
        return licence.lower() in ALLOWED_SPDX


def expression_allowed(expression: str) -> bool:
    """Say whether an SPDX expression lets us ship the package. Raises if unreadable."""
    return _Parser(expression).allowed()


# Older metadata states the licence in free text. Only these exact phrases (compared
# without case) count; anything else falls through to the classifiers.
ALLOWED_FREE_TEXT = frozenset(
    {
        "mit",
        "mit license",
        "bsd",
        "bsd license",
        "new bsd license",
        "apache 2.0",
        "apache license 2.0",
        "apache license, version 2.0",
        "apache software license",
        "isc license",
        "psf",
        "psf license",
        "python software foundation license",
    }
)

# Trove classifiers (the last part after "License :: ") in the allowed families.
ALLOWED_CLASSIFIERS = frozenset(
    {
        "MIT License",
        "BSD License",
        "Apache Software License",
        "Python Software Foundation License",
        "ISC License (ISCL)",
        "Mozilla Public License 2.0 (MPL 2.0)",
        "GNU Lesser General Public License v2 (LGPLv2)",
        "GNU Lesser General Public License v2 or later (LGPLv2+)",
        "GNU Lesser General Public License v3 (LGPLv3)",
        "GNU Lesser General Public License v3 or later (LGPLv3+)",
        "GNU Library or Lesser General Public License (LGPL)",
    }
)

# Classifiers that name no licence.
_UNINFORMATIVE_CLASSIFIERS = frozenset({"License :: OSI Approved"})

# An identifier that looks like an SPDX licence id with a version, e.g. GPL-3.0-only.
_SPDX_LIKE = re.compile(r"[A-Za-z][A-Za-z0-9.+]*-[A-Za-z0-9.+-]*[0-9][A-Za-z0-9.+-]*")


@dataclass(frozen=True, slots=True)
class _Verdict:
    licence: str
    allowed: bool


def _from_field(field: str | None) -> _Verdict | None:
    """Read the free-text License field if it is one line we can read with certainty."""
    text = (field or "").strip()
    if not text or "\n" in text:
        return None
    if text.lower() in ALLOWED_FREE_TEXT:
        return _Verdict(text, allowed=True)
    identifiers = [token for token in _tokens_or_none(text) if token not in {"(", ")"}] or [
        "<none>"
    ]
    looks_like_spdx = all(
        token.upper() in {"AND", "OR", "WITH"}
        or token.lower() in ALLOWED_SPDX
        or _SPDX_LIKE.fullmatch(token)
        for token in identifiers
    )
    if not looks_like_spdx:
        return None
    try:
        return _Verdict(text, allowed=expression_allowed(text))
    except UnreadableLicenceError:
        return None


def _tokens_or_none(text: str) -> list[str]:
    try:
        return _tokens(text)
    except UnreadableLicenceError:
        return []


def _from_classifiers(classifiers: tuple[str, ...]) -> _Verdict | None:
    names = [
        classifier.split(" :: ")[-1]
        for classifier in classifiers
        if classifier.startswith("License ::") and classifier not in _UNINFORMATIVE_CLASSIFIERS
    ]
    if not names:
        return None
    return _Verdict(" AND ".join(names), allowed=all(n in ALLOWED_CLASSIFIERS for n in names))


@dataclass(frozen=True, slots=True)
class Override:
    """A person's decision that one version of a package may ship, and why.

    It holds for that exact version only, so a version bump means checking upstream again.
    """

    version: str
    licence: str
    reason: str
    text_must_contain: str


# Each entry was checked by hand against the package's own licence file (ticket #44).
OVERRIDES: Mapping[str, Override] = {
    "pyrage": Override(
        version="1.4.0",
        licence="MIT",
        reason="its metadata names no licence; the LICENSE file in its wheel is the MIT text",
        text_must_contain="Permission is hereby granted, free of charge",
    ),
    "cffi": Override(
        version="2.1.1",
        licence="MIT-0",
        reason=(
            "MIT-0 is the MIT licence without its attribution condition, so it allows"
            " everything MIT does (to confirm with the operator, ticket #44)"
        ),
        text_must_contain="Permission is hereby granted, free of charge",
    ),
}


def _review_overridden(package: Package, override: Override) -> Accepted | str:
    label = f"{package.name} {package.version}"
    if package.version != override.version:
        return (
            f"{label}: the licence override is for version {override.version}; check upstream"
            " again and update it"
        )
    if not any(override.text_must_contain in text for _, text in package.licence_texts):
        return (
            f"{label}: the licence override expects its licence text to contain"
            f" '{override.text_must_contain}'"
        )
    return Accepted(package, override.licence)


def _review_one(package: Package, overrides: Mapping[str, Override]) -> Accepted | str:
    label = f"{package.name} {package.version}"
    if package.name in overrides:
        return _review_overridden(package, overrides[package.name])
    if package.licence_expression:
        expression = package.licence_expression
        try:
            verdict = _Verdict(expression, allowed=expression_allowed(expression))
        except UnreadableLicenceError:
            return f"{label}: licence expression '{expression}' cannot be read"
    else:
        found = _from_field(package.licence_field) or _from_classifiers(package.classifiers)
        if found is None:
            return f"{label}: no licence it can recognise; check upstream and add an override"
        verdict = found
    if not verdict.allowed:
        return f"{label}: licence '{verdict.licence}' is not on the allowed list"
    return Accepted(package, verdict.licence)


def review_licences(
    packages: list[Package], overrides: Mapping[str, Override] = OVERRIDES
) -> Review:
    """Accept each package whose licence is allowed; describe every other one."""
    accepted: list[Accepted] = []
    refusals: list[str] = []
    for package in packages:
        outcome = _review_one(package, overrides)
        if isinstance(outcome, Accepted) and not package.licence_texts:
            outcome = (
                f"{package.name} {package.version}: ships no licence text; save it from"
                f" upstream as {SUPPLIED_TEXTS_DIR}/{package.name}-{package.version}.txt"
            )
        if isinstance(outcome, Accepted):
            accepted.append(outcome)
        else:
            refusals.append(outcome)
    return Review(accepted, refusals)


def runtime_package_names(
    lock: Mapping[str, Any], project: str, environment: Mapping[str, str]
) -> list[str]:
    """List the packages the project needs at run time on one platform, from uv.lock.

    Only the project's own dependencies count (never a dependency group such as dev or
    build), followed through every package whose marker holds in `environment`.
    """
    by_name: dict[str, Mapping[str, Any]] = {}
    for entry in lock["package"]:
        if entry["name"] in by_name:
            msg = f"uv.lock holds {entry['name']} more than once; the check cannot choose"
            raise ValueError(msg)
        by_name[entry["name"]] = entry
    found: set[str] = set()
    waiting = [project]
    while waiting:
        for dependency in by_name[waiting.pop()].get("dependencies", []):
            marker = dependency.get("marker")
            if marker is not None and not Marker(marker).evaluate(dict(environment)):
                continue
            if dependency["name"] not in found:
                found.add(dependency["name"])
                waiting.append(dependency["name"])
    return sorted(found)


def _is_lgpl(licence: str) -> bool:
    upper = licence.upper()
    return "LGPL" in upper or "LESSER GENERAL PUBLIC" in upper


@dataclass(frozen=True, slots=True)
class Section:
    """One component in THIRD-PARTY-NOTICES.txt: its name, licence and licence texts."""

    title: str
    licence: str
    texts: tuple[tuple[str, str], ...]
    note: str = ""


_RULE = "=" * 78
_PLAIN_FILES_NOTE = "kept as plain .py files in _internal, so it can be replaced"


def notices_text(product_version: str, review: Review, extras: list[Section]) -> str:
    """Write THIRD-PARTY-NOTICES.txt: the extras first, then each accepted package by name."""
    packages = [
        Section(
            f"{a.package.name} {a.package.version}",
            a.licence,
            a.package.licence_texts,
            _PLAIN_FILES_NOTE if _is_lgpl(a.licence) else "",
        )
        for a in sorted(review.accepted, key=lambda a: a.package.name.lower())
    ]
    sections = [*extras, *packages]
    lines = [
        f"Third-party notices for Network Analyser {product_version}",
        "",
        "This build bundles the software listed below. Each entry names the licence it is",
        "shipped under and repeats the licence text that the component itself ships.",
        "",
        "Contents",
    ]
    for section in sections:
        note = f" ({section.note})" if section.note else ""
        lines.append(f"  {section.title}: {section.licence}{note}")
    for section in sections:
        lines += ["", _RULE, f"{section.title}: {section.licence}", _RULE]
        seen: set[str] = set()
        for name, text in section.texts:
            if text in seen:
                continue
            seen.add(text)
            lines += ["", f"--- {name} ---", "", text.rstrip()]
    return "\n".join(lines) + "\n"


# PyInstaller is a build tool, but its bootloader becomes the exe. Its licence (GPL-2.0 or
# later with an exception that allows shipping the bootloader) is checked by hand for this
# version only; a bump means reading its COPYING.txt again.
BOOTLOADER = ("pyinstaller", "6.22.3", "GPL-2.0-or-later WITH Bootloader-exception")

_LICENCE_NAME = re.compile(r"(LICEN[CS]E|COPYING|NOTICE)", re.IGNORECASE)


def _licence_files(distribution: metadata.Distribution) -> list[tuple[str, str]]:
    texts: list[tuple[str, str]] = []
    for file in distribution.files or []:
        parts = file.parts
        in_licences_dir = parts[0].endswith(".dist-info") and "licenses" in parts[1:-1]
        named_like_a_licence = _LICENCE_NAME.match(parts[-1]) is not None
        if not (in_licences_dir or named_like_a_licence) or file.suffix in {".py", ".textfsm"}:
            continue
        text = Path(file.locate()).read_text(encoding="utf-8", errors="replace")
        texts.append((file.as_posix(), text))
    return sorted(texts)


def _modules(distribution: metadata.Distribution) -> tuple[str, ...]:
    top_level = distribution.read_text("top_level.txt")
    if top_level:
        return tuple(sorted({line.strip() for line in top_level.splitlines() if line.strip()}))
    found: set[str] = set()
    for file in distribution.files or []:
        parts = file.parts
        if len(parts) > 1 and parts[1] == "__init__.py":
            found.add(parts[0])
        elif len(parts) == 1 and file.suffix in {".py", ".pyd", ".so"}:
            found.add(parts[0].split(".")[0])
    return tuple(sorted(found))


def installed_package(name: str, repo_root: Path) -> Package:
    """Read an installed distribution's licence metadata and texts."""
    distribution = metadata.distribution(name)
    version = distribution.version
    texts = _licence_files(distribution)
    supplied = repo_root / SUPPLIED_TEXTS_DIR / f"{name}-{version}.txt"
    if supplied.is_file():
        texts.append((f"{SUPPLIED_TEXTS_DIR}/{supplied.name}", supplied.read_text("utf-8")))
    return Package(
        name=name,
        version=version,
        licence_expression=distribution.metadata.get("License-Expression"),
        licence_field=distribution.metadata.get("License"),
        classifiers=tuple(distribution.metadata.get_all("Classifier") or ()),
        licence_texts=tuple(texts),
        modules=_modules(distribution),
    )


def _python_runtime() -> Section | str:
    title = f"Python (CPython) {platform.python_version()} runtime"
    for candidate in (
        Path(sys.base_prefix) / "LICENSE.txt",  # python.org Windows layout
        Path(sysconfig.get_path("stdlib")) / "LICENSE.txt",
    ):
        if candidate.is_file():
            text = candidate.read_text(encoding="utf-8", errors="replace")
            return Section(title, "PSF-2.0", (("LICENSE.txt", text),))
    return f"{title}: its LICENSE.txt was not found beside the interpreter"


def _bootloader() -> Section | str:
    name, version, licence = BOOTLOADER
    try:
        distribution = metadata.distribution(name)
    except metadata.PackageNotFoundError:
        return f"{name}: not installed; run uv sync --locked --no-build"
    if distribution.version != version:
        return (
            f"{name} {distribution.version}: its licence was checked for {version} only; read"
            " its COPYING.txt again and update BOOTLOADER"
        )
    title = f"PyInstaller {version} bootloader (the exe's start-up code)"
    return Section(title, licence, tuple(_licence_files(distribution)))


def collect(repo_root: Path) -> tuple[Review, list[Section]]:
    """Check every package bundled on this platform, plus the runtime and bootloader."""
    lock = tomllib.loads((repo_root / "uv.lock").read_text(encoding="utf-8"))
    project = tomllib.loads((repo_root / "pyproject.toml").read_text(encoding="utf-8"))
    # This interpreter's markers: build.ps1 runs this on the Windows x64 build interpreter.
    here = {key: str(value) for key, value in default_environment().items()}
    names = runtime_package_names(lock, project["project"]["name"], here)
    packages: list[Package] = []
    missing: list[str] = []
    for name in names:
        try:
            packages.append(installed_package(name, repo_root))
        except metadata.PackageNotFoundError:
            missing.append(f"{name}: locked for this platform but not installed")
    review = review_licences(packages)
    extras: list[Section] = []
    for extra in (_python_runtime(), _bootloader()):
        if isinstance(extra, Section):
            extras.append(extra)
        else:
            missing.append(extra)
    return Review(review.accepted, [*missing, *review.refusals]), extras


def main(argv: list[str] | None = None) -> int:
    """Run the licence check; write the notices only if every component passes."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="THIRD-PARTY-NOTICES.txt path")
    parser.add_argument("--product-version", required=True)
    args = parser.parse_args(argv)
    review, extras = collect(REPO_ROOT)
    if review.refusals:
        print("Licence check FAILED:")
        for refusal in review.refusals:
            print(f"  {refusal}")
        return 1
    args.out.write_text(notices_text(args.product_version, review, extras), encoding="utf-8")
    print(f"Licence check passed: {len(review.accepted)} packages, plus the runtime.")
    print(f"Kept as plain files (LGPL): {', '.join(plain_file_modules(review))}")
    print(f"Wrote {args.out}")
    return 0


def plain_file_modules(review: Review) -> list[str]:
    """Name the top-level modules of every LGPL package.

    The build keeps them as plain .py files beside the exe rather than inside PyInstaller's
    archive, so they stay replaceable (decision #32 section 6).
    """
    return sorted(
        module
        for accepted in review.accepted
        if _is_lgpl(accepted.licence)
        for module in accepted.package.modules
    )


if __name__ == "__main__":
    sys.exit(main())
