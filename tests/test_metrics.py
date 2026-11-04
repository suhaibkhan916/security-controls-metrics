import json
import sys
from datetime import date
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from metrics import compute, report  # noqa: E402

C = lambda i, sev, ok, ce="Secure configuration": {"id": i, "severity": sev, "passed": ok, "ce": ce}


def test_weighted_score_counts_high_severity_more():
    controls = [C("A", "high", False), C("B", "low", True), C("C", "low", True)]
    s = compute.control_scores(controls)
    assert s["pass_rate"] == pytest.approx(66.7)
    assert s["weighted_pass_rate"] == pytest.approx(40.0)  # 2 of 5 weighted points
    assert s["high_severity_failures"] == ["A"]


def test_control_scores_by_theme():
    s = compute.control_scores([C("A", "high", True, "Firewalls"), C("B", "low", False, "Firewalls")])
    assert s["by_ce_theme"]["Firewalls"] == {"passed": 1, "total": 2}


def test_vuln_metrics_separates_fixable_from_unfixable():
    v = compute.vuln_metrics({"total": 10, "fixable": 3, "by_severity": {"CRITICAL": 1, "HIGH": 2}}, baseline_fixable=12)
    assert v["no_fix_available"] == 7
    assert v["critical_and_high"] == 3
    assert v["fixable_remediated_pct"] == 75.0


def T(sev, opened, closed=""):
    return {"severity": sev, "opened": opened, "closed": closed}


def test_remediation_sla_counts_old_open_tickets_as_breaches():
    tickets = [T("high", "2026-10-01", "2026-10-05"),   # 4 days, within 14
               T("high", "2026-10-01", "2026-10-30"),   # 29 days, breached
               T("high", "2026-10-01"),                 # open 30 days at as_of: overdue
               T("high", "2026-10-28")]                 # open 3 days: not judged yet
    r = compute.remediation_metrics(tickets, date(2026, 10, 31))["high"]
    assert r["mean_days_to_fix"] == 16.5
    assert r["open_overdue"] == 1
    assert r["sla_compliance_pct"] == pytest.approx(33.3)  # 1 within of 3 judged


def test_remediation_without_closed_tickets():
    r = compute.remediation_metrics([T("low", "2026-10-30")], date(2026, 10, 31))["low"]
    assert r["mean_days_to_fix"] is None and r["sla_compliance_pct"] is None


def test_controls_file_is_complete_and_mapped():
    controls = yaml.safe_load((ROOT / "checks" / "controls.yaml").read_text(encoding="utf-8"))
    ids = [c["id"] for c in controls]
    assert len(ids) == len(set(ids))
    for c in controls:
        assert c["severity"] in compute.WEIGHT
        for key in ("check", "ce", "cis", "nist", "iso"):
            assert c.get(key), f"{c['id']} missing {key}"


@pytest.mark.skipif(not (ROOT / "results" / "metrics.json").exists(), reason="run the collection first")
def test_report_labels_synthetic_data_and_states_limits():
    text = report.render(json.loads((ROOT / "results" / "metrics.json").read_text(encoding="utf-8")))
    assert "SYNTHETIC" in text and "synthetic" in text
    assert "Method and limits" in text
    assert "—" not in text
