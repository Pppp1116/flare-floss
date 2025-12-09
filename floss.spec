# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files

block_cipher = None

project_root = Path(__file__).parent

data_files = collect_data_files(
    "floss",
    includes=["**/*.pat", "**/*.pat.gz", "**/*.sig", "sigs/README.md"],
)

data_files += [
    (str(project_root / "scripts" / "ghidra_floss_import.py"), "scripts"),
    (str(project_root / "scripts" / "ghidra_floss_export_hints.py"), "scripts"),
]

data_files += [
    (str(project_root / "resources" / "floss.ico"), "resources"),
    (str(project_root / "resources" / "floss-icon.png"), "resources"),
    (str(project_root / "resources" / "floss-logo.png"), "resources"),
]


a = Analysis(
    ["floss/__main__.py"],
    pathex=[str(project_root)],
    binaries=[],
    datas=data_files,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="floss",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="floss",
)
