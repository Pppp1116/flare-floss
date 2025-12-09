import pytest

from floss import identify
from floss.features import features


class DummyFeature(features.Feature):
    weight = features.MEDIUM

    def __init__(self, score_value: float):
        super().__init__(score_value)
        self._score_value = score_value

    def score(self) -> float:
        return self._score_value


def test_bonus_features_do_not_reduce_score():
    base_feature = DummyFeature(0.6)
    baseline = identify.get_function_score_weighted([base_feature])

    bonus_feature = features.XrefCount(1, 10)
    with_bonus = identify.get_function_score_weighted([base_feature, bonus_feature])

    assert with_bonus >= baseline


def test_bonus_heuristics_are_non_decreasing():
    class DummyInsn:
        va = 0x1000

        def __str__(self):
            return "rep movsb"

    base_feature = DummyFeature(0.5)
    baseline = identify.get_function_score_weighted([base_feature])

    low_bonus = features.XrefCount(1, 10)
    high_bonus = features.XrefCount(10, 10)
    buffer_bonus = features.BufferCopy(DummyInsn())

    with_low_bonus = identify.get_function_score_weighted([base_feature, low_bonus])
    with_high_bonus = identify.get_function_score_weighted([base_feature, high_bonus, buffer_bonus])

    assert with_low_bonus >= baseline
    assert with_high_bonus >= with_low_bonus


def test_bonus_is_capped():
    base_feature = DummyFeature(0.2)
    baseline = identify.get_function_score_weighted([base_feature])

    rich_bonus_features = [features.XrefCount(10, 10) for _ in range(10)]

    scored = identify.get_function_score_weighted([base_feature, *rich_bonus_features])

    assert scored - baseline <= identify.BONUS_CAP + 1e-6
    assert scored <= 1.0


def test_bonus_config_can_be_adjusted():
    base_feature = DummyFeature(0.2)
    bonus_feature = features.XrefCount(10, 10)

    default_scored = identify.get_function_score_weighted([base_feature, bonus_feature])

    custom_config = identify.BonusScoringConfig(weight_multiplier=0.6, cap=0.8)
    tuned_scored = identify.get_function_score_weighted([base_feature, bonus_feature], bonus_config=custom_config)

    assert tuned_scored >= default_scored
