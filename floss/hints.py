"""Utilities for working with FLOSS hint files.

Hints are optional and preserve baseline behavior when omitted or invalid.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Set

import floss.logging_

logger = floss.logging_.getLogger(__name__)


@dataclass(frozen=True)
class HintsMeta:
    floss_hints_version: int = 1
    program_hash: str = ""
    imagebase: int = 0
    generated_at: str = ""
    generator: str = ""


@dataclass(frozen=True)
class FlossHints:
    meta: HintsMeta = HintsMeta()
    force_candidates: Set[int] = field(default_factory=set)
    deprioritize_functions: Set[int] = field(default_factory=set)
    ignore_functions: Set[int] = field(default_factory=set)


EMPTY_HINTS = FlossHints()


def _parse_address_list(values: Iterable) -> Set[int]:
    addresses: Set[int] = set()
    for value in values or []:
        try:
            if isinstance(value, str):
                addresses.add(int(value, 0))
            else:
                addresses.add(int(value))
        except (TypeError, ValueError):
            continue
    return addresses


def _load_raw_hints(path: Path) -> dict:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError) as exc:
        logger.warning("failed to parse hints JSON at %s: %s", path, exc)
        return {}


def load_hints(
    path: Path,
    expected_hash: str,
    expected_imagebase: int,
    ignore_hash_mismatch: bool = False,
) -> FlossHints:
    """Load and validate hints from JSON.

    On any error or hash mismatch (unless ignored), EMPTY_HINTS is returned.
    """

    raw_hints = _load_raw_hints(path)
    if not raw_hints:
        return EMPTY_HINTS

    meta = raw_hints.get("meta", {}) or {}
    program_hash = (meta.get("program_hash") or "").lower()
    if program_hash and expected_hash:
        if program_hash != expected_hash.lower():
            message = "hints hash does not match sample; ignoring hints"
            if ignore_hash_mismatch:
                logger.warning("%s but proceeding due to override", message)
            else:
                logger.warning(message)
                return EMPTY_HINTS

    imagebase = meta.get("imagebase")
    if imagebase is not None and expected_imagebase:
        try:
            imagebase_int = int(imagebase, 0) if isinstance(imagebase, str) else int(imagebase)
        except (TypeError, ValueError):
            imagebase_int = None
        if imagebase_int is not None and imagebase_int != expected_imagebase:
            message = "hints imagebase does not match sample; ignoring hints"
            if ignore_hash_mismatch:
                logger.warning("%s but proceeding due to override", message)
            else:
                logger.warning(message)
                return EMPTY_HINTS

    hints_meta = HintsMeta(
        floss_hints_version=meta.get("floss_hints_version", 1),
        program_hash=program_hash,
        imagebase=meta.get("imagebase", 0),
        generated_at=meta.get("generated_at", ""),
        generator=meta.get("generator", ""),
    )

    hints = FlossHints(
        meta=hints_meta,
        force_candidates=_parse_address_list(raw_hints.get("force_candidates", [])),
        deprioritize_functions=_parse_address_list(raw_hints.get("deprioritize_functions", [])),
        ignore_functions=_parse_address_list(raw_hints.get("ignore_functions", [])),
    )

    logger.debug(
        "loaded hints from %s with %d forced, %d deprioritized, %d ignored entries",
        path,
        len(hints.force_candidates),
        len(hints.deprioritize_functions),
        len(hints.ignore_functions),
    )
    return hints
