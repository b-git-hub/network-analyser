# PyInstaller build of Network Analyser: one folder, no UPX, no strip (ticket #44, #32).
#
# build.ps1 runs it from the repo root:
#   python -m PyInstaller --noconfirm --clean --distpath dist --workpath build/pyinstaller
#       scripts/network_analyser.spec
#
# - LGPL packages (Paramiko, scp) are kept as plain .py files in _internal, outside the
#   packed archive, so they stay replaceable (decision #32 section 6). The list comes from
#   the licence check itself, so a new LGPL dependency is kept as plain files too.
# - The Windows version resource is written from network_analyser.__version__, the same
#   value `--version` prints (story 178).
# - The runtime dependencies are named as hidden imports so the build always carries
#   them, even while a module that will import them is still a stub.
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, copy_metadata

REPO_ROOT = Path(SPECPATH).resolve().parent  # noqa: F821 (SPECPATH is set by PyInstaller)
sys.path.insert(0, str(REPO_ROOT))

from network_analyser._version import __version__  # noqa: E402
from scripts.third_party_notices import collect, plain_file_modules  # noqa: E402
from scripts.version_resource import version_file_text  # noqa: E402

review, _ = collect(REPO_ROOT)
if review.refusals:
    raise SystemExit("The licence check failed: run python -m scripts.third_party_notices.")
PLAIN_FILES = plain_file_modules(review)
if "paramiko" not in PLAIN_FILES:
    raise SystemExit("Paramiko must be kept as plain files (LGPL), but it was not found.")

version_file = REPO_ROOT / "build" / "version_info.txt"
version_file.parent.mkdir(parents=True, exist_ok=True)
version_file.write_text(version_file_text(__version__), encoding="utf-8")

a = Analysis(  # noqa: F821
    [str(REPO_ROOT / "network_analyser" / "__main__.py")],
    pathex=[str(REPO_ROOT)],
    # #95: truststore picks a platform backend by `platform.system()`, so name it too.
    hiddenimports=["netmiko", "paramiko", "pyrage", "textfsm", "ntc_templates", "truststore"],
    # TextFSM templates, and any non-Python files of our own (such as the diagram's
    # JavaScript and CSS once they exist).
    # ntc_templates reads its own version from its metadata when imported.
    datas=collect_data_files("ntc_templates")
    + copy_metadata("ntc-templates")
    + collect_data_files("network_analyser"),
    # setuptools is in the build environment only because PyInstaller needs it; nothing
    # the tool runs imports it, so keep it (and its vendored copies) out of the build.
    excludes=[
        "tkinter",
        "scripts",
        "setuptools",
        "pkg_resources",
        "_distutils_hack",
        "distutils",
    ],
    module_collection_mode={
        # Netmiko finds the TextFSM templates folder through ntc_templates/parse.py, so
        # that package also keeps its source files on disk.
        "ntc_templates": "pyz+py",
        **{module: "py" for module in PLAIN_FILES},
    },
    noarchive=False,
)
pyz = PYZ(a.pure)  # noqa: F821
exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="network-analyser",
    console=True,
    debug=False,
    strip=False,
    upx=False,
    version=str(version_file),
)
coll = COLLECT(  # noqa: F821
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="network-analyser",
)
