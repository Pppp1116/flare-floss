from __future__ import annotations

from pathlib import Path

import pytest


def require_file(path: Path, *, allow_module_level: bool = False) -> Path:
    """Skip a test if the given file does not exist.

    This repository expects many binary fixtures that may be distributed via
    git-lfs or a separate test data repository. In environments where the
    files are not available, we skip the affected tests rather than failing
    the entire suite.
    """

    if not path.exists():
        pytest.skip(f"required test file not found: {path}", allow_module_level=allow_module_level)
    return path


def require_directory(path: Path, *, allow_module_level: bool = False) -> Path:
    """Skip a test when a directory of test fixtures is missing."""

    if not path.exists():
        pytest.skip(f"required test directory not found: {path}", allow_module_level=allow_module_level)
    return path

