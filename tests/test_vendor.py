import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from vendor import assess  # noqa: E402

QUESTIONS = [
    {"id": "Q1", "area": "Data protection", "text": "DPA?", "weight": 3, "must_have": True, "maps": ["UK GDPR Art 28"]},
    {"id": "Q2", "area": "Encryption", "text": "Encrypted?", "weight": 1, "maps": ["ISO 8.24"]},
]


def vendor(a1, a2, findings=()):
    return {"answers": {"Q1": {"answer": a1, "evidence": "e"}, "Q2": {"answer": a2, "evidence": "e"}},
            "pentest": {"date": "2026-01-01", "findings": list(findings)}}


def test_all_yes_is_approved():
    r = assess.assess(QUESTIONS, vendor("yes", "yes"))
    assert r["score"] == 100.0 and r["decision"] == "approve"


def test_must_have_no_blocks_approval():
    r = assess.assess(QUESTIONS, vendor("no", "yes"))
    assert r["decision"] == "reject" and r["blocking"]


def test_must_have_partial_is_a_condition_not_a_block():
    r = assess.assess(QUESTIONS, vendor("partial", "yes"))
    assert r["score"] == 62.5  # (0.5 * 3 + 1) / 4
    assert r["decision"] == "approve_with_conditions"
    assert r["conditions"] and not r["blocking"]


def test_open_high_pentest_finding_becomes_a_condition():
    r = assess.assess(QUESTIONS, vendor("yes", "yes", [{"id": "PT", "title": "XSS", "severity": "high", "status": "open"}]))
    assert r["decision"] == "approve_with_conditions"
    assert any("PT open high" in c for c in r["conditions"])


def test_fixed_findings_do_not_count():
    r = assess.assess(QUESTIONS, vendor("yes", "yes", [{"id": "PT", "title": "XSS", "severity": "critical", "status": "fixed"}]))
    assert r["decision"] == "approve"


@pytest.mark.parametrize("raw,expected", [(True, "yes"), (False, "no"), ("Partial ", "partial")])
def test_yaml_booleans_are_normalised(raw, expected):
    assert assess.normalise(raw) == expected


def test_unknown_answer_is_rejected():
    with pytest.raises(ValueError):
        assess.normalise("maybe")


def test_unquoted_yes_in_yaml_still_scores():
    v = yaml.safe_load("answers:\n  Q1: {answer: yes, evidence: e}\n  Q2: {answer: no, evidence: e}\n")
    r = assess.assess(QUESTIONS, v)
    assert r["score"] == 75.0
