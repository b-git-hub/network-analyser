"""The build's licence check and THIRD-PARTY-NOTICES.txt (ticket #44, decision #32 section 6).

Packages here are synthetic: names, versions and licence texts are made up.
"""

from scripts.third_party_notices import (
    Override,
    Package,
    Section,
    collect,
    notices_text,
    plain_file_modules,
    review_licences,
    runtime_package_names,
)
from tests.support.source_scan import REPO_ROOT

MIT_TEXT = "Permission is hereby granted, free of charge, to any person (synthetic MIT text)"


def package(  # noqa: PLR0913 (a test builder with a default for every field)
    name: str = "alpha",
    version: str = "1.0.0",
    *,
    expression: str | None = None,
    licence: str | None = None,
    classifiers: tuple[str, ...] = (),
    texts: tuple[tuple[str, str], ...] = (("LICENSE", MIT_TEXT),),
    modules: tuple[str, ...] = ("alpha",),
) -> Package:
    return Package(
        name=name,
        version=version,
        licence_expression=expression,
        licence_field=licence,
        classifiers=classifiers,
        licence_texts=texts,
        modules=modules,
    )


def test_a_package_under_an_allowed_spdx_expression_is_accepted() -> None:
    review = review_licences([package(expression="MIT")])

    assert review.refusals == []
    assert [(a.package.name, a.licence) for a in review.accepted] == [("alpha", "MIT")]


def test_an_or_expression_needs_one_allowed_choice_and_and_needs_all() -> None:
    review = review_licences(
        [
            package("alpha", expression="Apache-2.0 OR BSD-3-Clause"),
            package("bravo", expression="(GPL-3.0-only OR mit)"),
            package("charlie", expression="MIT AND GPL-3.0-only"),
            package("delta", expression="LGPL-2.1-or-later AND (ISC OR MPL-2.0)"),
        ]
    )

    assert [a.package.name for a in review.accepted] == ["alpha", "bravo", "delta"]
    assert review.refusals == [
        "charlie 1.0.0: licence 'MIT AND GPL-3.0-only' is not on the allowed list"
    ]


def test_a_disallowed_or_unreadable_expression_is_refused() -> None:
    review = review_licences(
        [
            package("alpha", expression="GPL-2.0-or-later"),
            package("bravo", expression="MIT OR"),
        ]
    )

    assert review.accepted == []
    assert review.refusals == [
        "alpha 1.0.0: licence 'GPL-2.0-or-later' is not on the allowed list",
        "bravo 1.0.0: licence expression 'MIT OR' cannot be read",
    ]


def test_without_an_expression_the_licence_field_then_the_classifiers_decide() -> None:
    osi = "License :: OSI Approved :: "
    review = review_licences(
        [
            package("alpha", licence="LGPL-2.1-or-later"),
            package("bravo", licence="Apache License, Version 2.0"),
            package("charlie", licence="BSD"),
            package("delta", licence="See the LICENSE file", classifiers=(f"{osi}MIT License",)),
            package("echo", classifiers=(f"{osi}BSD License", f"{osi}Apache Software License")),
            package("foxtrot", licence="GPL-3.0-only", classifiers=(f"{osi}MIT License",)),
            package(
                "golf", classifiers=(f"{osi}MIT License", f"{osi}GNU General Public License (GPL)")
            ),
            package("hotel", licence="Custom", classifiers=("License :: OSI Approved",)),
        ]
    )

    assert [(a.package.name, a.licence) for a in review.accepted] == [
        ("alpha", "LGPL-2.1-or-later"),
        ("bravo", "Apache License, Version 2.0"),
        ("charlie", "BSD"),
        ("delta", "MIT License"),
        ("echo", "BSD License AND Apache Software License"),
    ]
    assert review.refusals == [
        "foxtrot 1.0.0: licence 'GPL-3.0-only' is not on the allowed list",
        (
            "golf 1.0.0: licence 'MIT License AND GNU General Public License (GPL)' is not on"
            " the allowed list"
        ),
        "hotel 1.0.0: no licence it can recognise; check upstream and add an override",
    ]


SYNTHETIC_LOCK = {
    "package": [
        {
            "name": "tool",
            "version": "0.1.0",
            "source": {"virtual": "."},
            "dependencies": [
                {"name": "alpha"},
                {"name": "bravo", "marker": "sys_platform == 'win32'"},
            ],
            "dev-dependencies": {"dev": [{"name": "delta"}]},
        },
        {"name": "alpha", "version": "1.0", "dependencies": [{"name": "charlie"}]},
        {"name": "bravo", "version": "1.0"},
        {
            "name": "charlie",
            "version": "1.0",
            "dependencies": [
                {"name": "echo", "marker": "platform_python_implementation != 'PyPy'"},
                {"name": "alpha"},
            ],
        },
        {"name": "delta", "version": "1.0", "dependencies": [{"name": "foxtrot"}]},
        {"name": "echo", "version": "1.0"},
        {"name": "foxtrot", "version": "1.0"},
    ]
}


def environment(sys_platform: str) -> dict[str, str]:
    return {
        "sys_platform": sys_platform,
        "platform_python_implementation": "CPython",
        "implementation_name": "cpython",
    }


def test_the_bundled_packages_are_the_runtime_closure_for_the_target_platform() -> None:
    assert runtime_package_names(SYNTHETIC_LOCK, "tool", environment("win32")) == [
        "alpha",
        "bravo",
        "charlie",
        "echo",
    ]
    assert runtime_package_names(SYNTHETIC_LOCK, "tool", environment("linux")) == [
        "alpha",
        "charlie",
        "echo",
    ]


def test_lgpl_packages_are_the_ones_kept_as_plain_files() -> None:
    lesser = "License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)"
    review = review_licences(
        [
            package("alpha", expression="LGPL-2.1", modules=("alpha",)),
            package("bravo", expression="MIT", modules=("bravo",)),
            package("charlie", classifiers=(lesser,), modules=("charlie_one", "charlie_two")),
        ]
    )

    assert plain_file_modules(review) == ["alpha", "charlie_one", "charlie_two"]


def test_the_notices_list_every_component_then_give_each_licence_text_once() -> None:
    review = review_licences(
        [
            package("bravo", "2.0", expression="LGPL-2.1", texts=(("COPYING", "LGPL text"),)),
            package(
                "alpha",
                expression="MIT",
                texts=(("LICENSE", MIT_TEXT), ("licenses/LICENSE", MIT_TEXT)),
            ),
        ]
    )
    runtime = Section("Python runtime 3.14.0", "PSF-2.0", (("LICENSE.txt", "PSF text"),))

    text = notices_text("0.9.1", review, [runtime])

    assert text.startswith("Third-party notices for Network Analyser 0.9.1\n")
    contents = text[text.index("Contents") : text.index("=====")]
    assert contents.splitlines()[1:4] == [
        "  Python runtime 3.14.0: PSF-2.0",
        "  alpha 1.0.0: MIT",
        "  bravo 2.0: LGPL-2.1 (kept as plain .py files in _internal, so it can be replaced)",
    ]
    assert text.count(MIT_TEXT) == 1
    assert text.index("PSF text") < text.index(MIT_TEXT) < text.index("LGPL text")
    assert text.endswith("\n")


def test_the_locked_dependencies_installed_here_pass_the_check() -> None:
    # Reads this environment's installed package metadata: a dependency bump that brings
    # in a licence outside the allowed list fails here, before anyone runs build.ps1.
    review, extras = collect(REPO_ROOT)

    assert review.refusals == []
    assert {"netmiko", "paramiko", "pyrage", "scp"} <= {a.package.name for a in review.accepted}
    assert [section.title.split()[0] for section in extras] == ["Python", "PyInstaller"]
    assert {"paramiko", "scp"} <= set(plain_file_modules(review))


def test_a_package_without_any_licence_text_is_refused() -> None:
    review = review_licences([package("alpha", "2.0", expression="MIT", texts=())])

    assert review.accepted == []
    assert review.refusals == [
        (
            "alpha 2.0: ships no licence text; save it from upstream as"
            " scripts/licence_texts/alpha-2.0.txt"
        )
    ]


def test_an_override_applies_only_to_its_version_and_only_with_the_expected_text() -> None:
    overrides = {
        "alpha": Override("1.0.0", "MIT", "metadata names no licence", "free of charge"),
        "bravo": Override("1.0.0", "MIT", "metadata names no licence", "free of charge"),
        "charlie": Override("1.0.0", "MIT", "metadata names no licence", "free of charge"),
    }
    review = review_licences(
        [
            package("alpha"),
            package("bravo", "1.1.0"),
            package("charlie", texts=(("LICENSE", "All rights reserved."),)),
        ],
        overrides,
    )

    assert [(a.package.name, a.licence) for a in review.accepted] == [("alpha", "MIT")]
    assert review.refusals == [
        (
            "bravo 1.1.0: the licence override is for version 1.0.0; check upstream again and"
            " update it"
        ),
        "charlie 1.0.0: the licence override expects its licence text to contain 'free of charge'",
    ]
