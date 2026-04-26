from __future__ import annotations

from pathlib import Path

from tools.ci_gate import run_gate
from tools.evaluate_ai_generated_code import evaluate_ai_generated_code
from tools.evaluate_patcher import evaluate_patcher
from tools.evaluate_scanner import evaluate_scanner
from tools.evaluate_secrets import evaluate_secrets

ROOT = Path(__file__).resolve().parents[1]


def test_scanner_evaluator_reports_metrics():
    payload = evaluate_scanner(ROOT / 'dataset' / 'slayer-bench-v0', 'v1')
    assert payload['scanner']['precision'] >= 0.5
    assert 'NO_NETWORK' in payload['by_rule']


def test_patcher_evaluator_reports_metrics():
    payload = evaluate_patcher(ROOT / 'dataset' / 'slayer-bench-v0', 'v1')
    assert payload['patcher']['syntax_pass_rate'] >= 0.5
    assert payload['cases']


def test_ai_and_secret_evaluators_and_gate_run():
    ai_payload = evaluate_ai_generated_code(ROOT / 'dataset' / 'ai-bench-v0', 'v1')
    secret_payload = evaluate_secrets(ROOT / 'dataset' / 'slayer-bench-v0', 'v1')
    gate = run_gate('v1')
    assert ai_payload['ai_code']['recall'] >= 0.5
    assert secret_payload['secrets']['precision'] >= 0.5
    assert 'checks' in gate
