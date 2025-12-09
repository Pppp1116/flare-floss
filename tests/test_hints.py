import json
from pathlib import Path

import pytest

from floss import identify
from floss.hints import FlossHints, load_hints, EMPTY_HINTS


def test_apply_hint_scores_respects_baseline():
    candidates = {
        0x1000: {"score": 0.5, "score_components": {"base": 0.3, "bonus": 0.2}, "xrefs_to": 1, "features": []}
    }
    hints = FlossHints()

    adjusted = identify.apply_hint_scores(candidates, hints)
    assert adjusted[0x1000]["score"] == pytest.approx(candidates[0x1000]["score"])


def test_apply_hint_scores_injects_forced_candidates():
    candidates = {
        0x1000: {"score": 0.5, "score_components": {"base": 0.3, "bonus": 0.2}, "xrefs_to": 1, "features": []}
    }
    hints = FlossHints(force_candidates={0x2000})

    adjusted = identify.apply_hint_scores(candidates, hints, valid_fvas=(0x1000, 0x2000))
    assert 0x2000 in adjusted
    assert adjusted[0x2000]["score"] > 0
    assert adjusted[0x1000]["score"] >= candidates[0x1000]["score"]


def test_apply_hint_scores_respects_ignore_flag():
    hints = FlossHints(ignore_functions={0x1000})
    candidates = {
        0x1000: {"score": 0.5, "score_components": {"base": 0.3, "bonus": 0.2}, "xrefs_to": 1, "features": []},
        0x2000: {"score": 0.4, "score_components": {"base": 0.2, "bonus": 0.2}, "xrefs_to": 1, "features": []},
    }

    adjusted = identify.apply_hint_scores(candidates, hints, ignore_functions=True)
    assert 0x1000 not in adjusted
    assert 0x2000 in adjusted


def test_load_hints_validates_hash(tmp_path: Path):
    hints_file = tmp_path / "hints.json"
    content = {
        "meta": {"program_hash": "deadbeef", "imagebase": 0x1000},
        "force_candidates": ["0x2000"],
    }
    hints_file.write_text(json.dumps(content))

    hints = load_hints(hints_file, expected_hash="deadbeef", expected_imagebase=0x1000)
    assert hints.force_candidates == {0x2000}

    mismatched = load_hints(hints_file, expected_hash="aaaa", expected_imagebase=0x1000)
    assert mismatched == EMPTY_HINTS

    override = load_hints(hints_file, expected_hash="aaaa", expected_imagebase=0x1000, ignore_hash_mismatch=True)
    assert override.force_candidates == {0x2000}
