"""Utilities for locating FLOSS resources in source and frozen builds."""

from __future__ import annotations

import sys
from importlib import resources
from pathlib import Path


def is_frozen() -> bool:
    """Return True when running from a frozen/packaged build (e.g. PyInstaller)."""

    return getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS")


def get_base_path() -> Path:
    """
    Resolve the base directory that contains FLOSS resources.

    * Frozen (PyInstaller) builds expose resources relative to ``sys._MEIPASS``.
    * Source installs resolve to the package directory (``importlib.resources``).
    """

    if is_frozen():
        return Path(getattr(sys, "_MEIPASS"))

    return Path(resources.files("floss"))


def resource_path(*parts: str) -> Path:
    """
    Resolve a resource path that works in both source and frozen environments.

    The lookup prefers the package directory and falls back to the project root
    (useful for top-level helper scripts that are bundled alongside the package).
    """

    base_path = get_base_path()
    candidate = base_path.joinpath(*parts)
    if candidate.exists():
        return candidate

    fallback = base_path.parent.joinpath(*parts)
    return fallback
