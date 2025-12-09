import types

import pytest

from floss.features.extract import extract_insn_buffer_copy
from floss.features.features import BufferCopy, XrefCount


def test_buffer_copy_detection_captures_rep_movs():
    insn = types.SimpleNamespace(mnem="rep movsb", va=0x401000)
    features = list(extract_insn_buffer_copy(None, None, insn))
    assert any(isinstance(f, BufferCopy) for f in features)


@pytest.mark.parametrize(
    "xref_count,max_count,expected",
    [
        (0, 10, 0.0),
        (5, 10, 0.5),
        (10, 10, 1.0),
        (3, 0, 3 / 1),
    ],
)
def test_xref_count_scores_are_normalized(xref_count, max_count, expected):
    feature = XrefCount(xref_count, max_count)
    assert feature.score() == pytest.approx(expected)
