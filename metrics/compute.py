"""Turn collected evidence into control-effectiveness metrics.

All functions are pure (data in, numbers out) so they are unit-tested in tests/.

Remediation SLAs: critical and high within 14 days (the Cyber Essentials requirement for high-risk and
critical updates), medium 30 days and low 90 days (example internal policy, adjust to the organisation).
"""
import csv
import json
from collections import defaultdict
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WEIGHT = {"high": 3, "medium": 2, "low": 1}
SLA_DAYS = {"critical": 14, "high": 14, "medium": 30, "low": 90}


def control_scores(controls):
    """Pass rate overall, weighted by severity, and per Cyber Essentials theme."""
    total = len(controls)
    passed = sum(c["passed"] for c in controls)
    w_all = sum(WEIGHT[c["severity"]] for c in controls)
    w_pass = sum(WEIGHT[c["severity"]] for c in controls if c["passed"])
    by_theme = defaultdict(lambda: [0, 0])
    for c in controls:
        by_theme[c["ce"]][1] += 1
        by_theme[c["ce"]][0] += c["passed"]
    return {
        "passed": passed, "total": total,
        "pass_rate": round(100 * passed / total, 1) if total else 0.0,
        "weighted_pass_rate": round(100 * w_pass / w_all, 1) if w_all else 0.0,
        "high_severity_failures": [c["id"] for c in controls if not c["passed"] and c["severity"] == "high"],
        "by_ce_theme": {k: {"passed": v[0], "total": v[1]} for k, v in sorted(by_theme.items())},
    }


def vuln_metrics(trivy, baseline_fixable=None):
    """Vulnerability exposure. 'Fixable outstanding' is the patch-management measure; the rest have no
    fix released yet and need a risk decision instead of a patch."""
    out = {"total": trivy["total"], "by_severity": trivy["by_severity"], "fixable_outstanding": trivy["fixable"],
           "no_fix_available": trivy["total"] - trivy["fixable"],
           "critical_and_high": trivy["by_severity"].get("CRITICAL", 0) + trivy["by_severity"].get("HIGH", 0)}
    if baseline_fixable:
        out["fixable_remediated_pct"] = round(100 * (baseline_fixable - trivy["fixable"]) / baseline_fixable, 1)
    return out


def remediation_metrics(tickets, as_of):
    """Mean time to remediate and SLA compliance by severity, from tracker rows.
    An open ticket counts against the SLA once it is older than the SLA."""
    out = {}
    for sev, sla in SLA_DAYS.items():
        rows = [t for t in tickets if t["severity"] == sev]
        if not rows:
            continue
        closed = [(date.fromisoformat(t["closed"]) - date.fromisoformat(t["opened"])).days for t in rows if t["closed"]]
        open_age = [(as_of - date.fromisoformat(t["opened"])).days for t in rows if not t["closed"]]
        within = sum(d <= sla for d in closed)
        breached = sum(d > sla for d in closed) + sum(a > sla for a in open_age)
        judged = within + breached  # open tickets still inside their SLA are not judged yet
        out[sev] = {"tickets": len(rows), "closed": len(closed), "open": len(open_age), "sla_days": sla,
                    "mean_days_to_fix": round(sum(closed) / len(closed), 1) if closed else None,
                    "sla_compliance_pct": round(100 * within / judged, 1) if judged else None,
                    "open_overdue": sum(a > sla for a in open_age)}
    return out


def load_tracker(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def build(as_of=date(2026, 10, 31)):
    res = {}
    for state in ("baseline", "hardened"):
        d = ROOT / "results" / state
        res[state] = {k: json.loads((d / f"{k}.json").read_text(encoding="utf-8")) for k in ("controls", "lynis", "trivy")}
    base_fix = res["baseline"]["trivy"]["fixable"]
    metrics = {"as_of": as_of.isoformat(), "states": {}}
    for state, r in res.items():
        metrics["states"][state] = {
            "collected_at": r["controls"]["collected_at"],
            "controls": control_scores(r["controls"]["controls"]),
            "lynis": {k: r["lynis"][k] for k in ("hardening_index", "warnings", "suggestions")},
            "vulnerabilities": vuln_metrics(r["trivy"], base_fix if state == "hardened" else None),
        }
    metrics["remediation"] = remediation_metrics(load_tracker(ROOT / "data" / "remediation_tracker.csv"), as_of)
    metrics["remediation_data"] = "SYNTHETIC (data/generate_tracker.py, seed 2026)"
    return metrics


if __name__ == "__main__":
    m = build()
    (ROOT / "results" / "metrics.json").write_text(json.dumps(m, indent=1), encoding="utf-8")
    print(json.dumps({s: {"controls": v["controls"]["pass_rate"], "weighted": v["controls"]["weighted_pass_rate"],
                          "fixable_outstanding": v["vulnerabilities"]["fixable_outstanding"]} for s, v in m["states"].items()}))
