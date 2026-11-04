"""Write the one-page security metrics report from results/metrics.json.

usage: python metrics/report.py  ->  reports/security_metrics_report.md

Written for a CISO or risk committee: what changed, what is still exposed, what to do next.
Recommendations are generated from the numbers, so the report cannot say more than the data.
"""
import csv
import json
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SLA_TARGET = 90  # % of tickets fixed within SLA, example target


def overdue_by_owner(as_of, sla_days):
    rows = list(csv.DictReader(open(ROOT / "data" / "remediation_tracker.csv", encoding="utf-8")))
    out = {}
    for r in rows:
        if r["closed"]:
            continue
        if (as_of - date.fromisoformat(r["opened"])).days > sla_days[r["severity"]] and r["severity"] in ("critical", "high"):
            out.setdefault(r["owner"], []).append(r["ticket"])
    return out


def pct(v):
    return "n/a" if v is None else f"{v:.1f}%"


def render(m):
    b, h = m["states"]["baseline"], m["states"]["hardened"]
    rem = m["remediation"]
    as_of = date.fromisoformat(m["as_of"])
    sla_days = {k: v["sla_days"] for k, v in rem.items()}
    lines = [
        "# Security controls effectiveness report",
        "",
        f"Scope: one Debian server (lab target), baseline vs hardened and patched. Report date {m['as_of']}.",
        f"Remediation figures use {m['remediation_data']} data; control, Lynis and vulnerability figures are real tool output.",
        "",
        "## Summary",
        f"- Control pass rate rose from **{b['controls']['pass_rate']:.0f}%** to **{h['controls']['pass_rate']:.0f}%** "
        f"({h['controls']['passed']}/{h['controls']['total']} controls).",
        f"- Fixable vulnerabilities outstanding fell from **{b['vulnerabilities']['fixable_outstanding']}** to "
        f"**{h['vulnerabilities']['fixable_outstanding']}** ({pct(h['vulnerabilities'].get('fixable_remediated_pct'))} remediated).",
        f"- **{h['vulnerabilities']['no_fix_available']}** vulnerabilities remain with no fix released "
        f"({h['vulnerabilities']['critical_and_high']} critical or high): these need a risk decision, not a patch.",
        f"- Lynis hardening index moved only {b['lynis']['hardening_index']} to {h['lynis']['hardening_index']} while warnings fell "
        f"{b['lynis']['warnings']} to {h['lynis']['warnings']}: a generic benchmark score is not a substitute for control-level measures.",
        "",
        "## Key measures",
        "| Measure | Baseline | Current |",
        "|---|---|---|",
        f"| Controls passed | {b['controls']['passed']}/{b['controls']['total']} | {h['controls']['passed']}/{h['controls']['total']} |",
        f"| Weighted control score (high=3, medium=2, low=1) | {b['controls']['weighted_pass_rate']:.0f}% | {h['controls']['weighted_pass_rate']:.0f}% |",
        f"| High-severity control failures | {len(b['controls']['high_severity_failures'])} | {len(h['controls']['high_severity_failures'])} |",
        f"| Vulnerabilities, critical / high | {b['vulnerabilities']['by_severity']['CRITICAL']} / {b['vulnerabilities']['by_severity']['HIGH']} "
        f"| {h['vulnerabilities']['by_severity']['CRITICAL']} / {h['vulnerabilities']['by_severity']['HIGH']} |",
        f"| Fixable vulnerabilities outstanding | {b['vulnerabilities']['fixable_outstanding']} | {h['vulnerabilities']['fixable_outstanding']} |",
        f"| Lynis hardening index / warnings | {b['lynis']['hardening_index']} / {b['lynis']['warnings']} | {h['lynis']['hardening_index']} / {h['lynis']['warnings']} |",
        "",
        "## Cyber Essentials themes (current)",
        "| Theme | Passed |",
        "|---|---|",
        *[f"| {t} | {v['passed']}/{v['total']} |" for t, v in h["controls"]["by_ce_theme"].items()],
        "",
        f"## Remediation performance ({m['remediation_data'].split(' ')[0].lower()} tracker)",
        "| Severity | SLA | Tickets | Open | Mean days to fix | Within SLA | Open and overdue |",
        "|---|---|---|---|---|---|---|",
        *[f"| {s} | {v['sla_days']} days | {v['tickets']} | {v['open']} | {v['mean_days_to_fix'] if v['mean_days_to_fix'] is not None else 'n/a'} "
          f"| {pct(v['sla_compliance_pct'])} | {v['open_overdue']} |" for s, v in rem.items()],
        "",
        "## Recommendations",
    ]
    recs = []
    if h["controls"]["high_severity_failures"]:
        recs.append(f"Fix high-severity control failures first: {', '.join(h['controls']['high_severity_failures'])}.")
    for sev in ("critical", "high"):
        v = rem.get(sev)
        if v and v["sla_compliance_pct"] is not None and v["sla_compliance_pct"] < SLA_TARGET:
            recs.append(f"{sev.title()} remediation within {v['sla_days']} days is {pct(v['sla_compliance_pct'])} against a {SLA_TARGET}% target; "
                        "Cyber Essentials requires high-risk and critical updates within 14 days.")
    owners = overdue_by_owner(as_of, sla_days)
    if owners:
        recs.append("Chase overdue critical and high tickets with their owners: " +
                    "; ".join(f"{o} ({', '.join(t)})" for o, t in sorted(owners.items())) + ".")
    if h["vulnerabilities"]["no_fix_available"]:
        recs.append(f"Record a risk decision for the {h['vulnerabilities']['no_fix_available']} unfixable vulnerabilities: "
                    "accept with an expiry date, reduce exposure (remove the package, restrict network access), and re-scan when fixes ship.")
    recs.append("Track these measures monthly; one snapshot shows a change, a trend shows whether controls are holding.")
    lines += [f"{i}. {r}" for i, r in enumerate(recs, 1)]
    lines += ["", "## Method and limits",
              "- Controls: 12 checks in checks/controls.yaml, each mapped to Cyber Essentials, CIS Controls v8, NIST CSF 2.0 and ISO/IEC 27001:2022 Annex A.",
              "- Lynis 3.0.8 system audit inside a container: kernel, boot and service checks do not apply there, which limits the index.",
              "- Trivy 0.57.1 image scan, OS packages only.",
              "- Firewall and audit controls check configuration files; containers do not load nftables or run auditd.",
              "- The Cyber Essentials malware protection theme is not measured: an anti-malware agent does not run meaningfully in this container.",
              "- Remediation figures are synthetic and illustrate the method, not a real organisation."]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    m = json.loads((ROOT / "results" / "metrics.json").read_text(encoding="utf-8"))
    out = ROOT / "reports" / "security_metrics_report.md"
    out.write_text(render(m), encoding="utf-8")
    print(out)
