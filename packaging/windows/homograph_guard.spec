# PyInstaller spec: four programs sharing one Python runtime (onedir).
#   HomographGuard.exe   desktop window (no console)
#   homograph-guard.exe  command line, and the window's isolated worker
#   hg-native-host.exe   browser extension helper (native messaging over stdin/stdout)
#   hg-update.exe        threat-database updater (no console; daily task)
# Build with packaging/windows/build.ps1.
import os
import sys

from PyInstaller.utils.hooks import collect_data_files, collect_submodules
from PyInstaller.utils.win32.versioninfo import (
    FixedFileInfo, StringFileInfo, StringStruct, StringTable, VarFileInfo, VarStruct, VSVersionInfo,
)

HERE = os.path.dirname(os.path.abspath(SPEC))  # noqa: F821 - provided by PyInstaller
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "src"))
from homograph_guard import __version__  # noqa: E402

NUMS = tuple(int(x) for x in __version__.split(".")) + (0,)
ICON = os.path.join(HERE, "app.ico")


def version(description, name):
    return VSVersionInfo(
        ffi=FixedFileInfo(filevers=NUMS, prodvers=NUMS),
        kids=[StringFileInfo([StringTable("040904B0", [
            StringStruct("CompanyName", "Homograph Guard"),
            StringStruct("FileDescription", description),
            StringStruct("FileVersion", __version__),
            StringStruct("InternalName", name),
            StringStruct("OriginalFilename", f"{name}.exe"),
            StringStruct("ProductName", "Homograph Guard"),
            StringStruct("ProductVersion", __version__),
            StringStruct("LegalCopyright", "MIT License"),
        ])]), VarFileInfo([VarStruct("Translation", [1033, 1200])])],
    )


common = dict(
    pathex=[os.path.join(ROOT, "src")],
    datas=collect_data_files("homograph_guard") + collect_data_files("publicsuffixlist"),
    hiddenimports=collect_submodules("dns.rdtypes") + ["homograph_guard.gui.lists"],
    excludes=["pytest", "_pytest", "unittest", "pydoc", "doctest", "lib2to3", "test"],
    noarchive=False,
)
programs = [
    ("entry_gui.py", "HomographGuard", "Homograph Guard", False),
    ("entry_cli.py", "homograph-guard", "Homograph Guard command line", True),
    ("entry_host.py", "hg-native-host", "Homograph Guard browser helper", True),
    ("entry_update.py", "hg-update", "Homograph Guard threat database updater", False),
]
parts = []
for script, name, description, console in programs:
    a = Analysis([os.path.join(HERE, script)], **common)  # noqa: F821
    pyz = PYZ(a.pure)  # noqa: F821
    exe = EXE(  # noqa: F821
        pyz, a.scripts, [], exclude_binaries=True, name=name, console=console, icon=ICON,
        version=version(description, name), disable_windowed_traceback=True, upx=False,
    )
    parts += [exe, a.binaries, a.datas]

coll = COLLECT(*parts, name="HomographGuard", upx=False)  # noqa: F821
