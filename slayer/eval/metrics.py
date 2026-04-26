from __future__ import annotations

from pydantic import BaseModel


class Scorecard(BaseModel):
    precision: float
    recall: float
    f1: float


class LocalizationMetrics(BaseModel):
    line_localization_accuracy: float


class PatchMetrics(BaseModel):
    syntax_pass_rate: float
    rescan_pass_rate: float
    minimal_diff_rate: float


def _safe_div(numerator: float, denominator: float) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def compute_scorecard(tp: int, fp: int, fn: int) -> Scorecard:
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    return Scorecard(precision=precision, recall=recall, f1=f1)


def compute_localization_metrics(localized_hits: int, total_expected_hits: int) -> LocalizationMetrics:
    return LocalizationMetrics(line_localization_accuracy=_safe_div(localized_hits, total_expected_hits))


def compute_patch_metrics(syntax_passes: int, rescan_passes: int, minimal_diffs: int, total_cases: int) -> PatchMetrics:
    return PatchMetrics(
        syntax_pass_rate=_safe_div(syntax_passes, total_cases),
        rescan_pass_rate=_safe_div(rescan_passes, total_cases),
        minimal_diff_rate=_safe_div(minimal_diffs, total_cases),
    )
