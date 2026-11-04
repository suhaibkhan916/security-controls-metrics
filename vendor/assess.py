"""Score a supplier against the question bank and its pen-test summary, and recommend a decision.

usage: python vendor/assess.py [vendor/example_vendor.yaml]  ->  vendor/assessment_report.md

Scoring: yes = full weight, partial = half, no = 0. Any must-have not answered "yes" is a condition
of approval. Open high or critical pen-test findings are conditions too. The decision is:
  approve              score >= 80, no conditions
  approve_with_conditions  score >= 60, or any conditions that can be fixed before go-live
  reject               score < 60, or a must-have answered "no"
"""
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CREDIT = {"yes": 1.0, "partial": 0.5, "no": 0.0}


def normalise(answer):
    """YAML 1.1 reads unquoted yes/no as booleans, so accept both forms."""
    if answer is True:
        return "yes"
    if answer is False:
        return "no"
    answer = str(answer).strip().lower()
    if answer not in CREDIT:
        raise ValueError(f"answer must be yes, partial or no, got {answer!r}")
    return answer


def assess(questions, vendor):
    answers = vendor["answers"]
    got = total = 0.0
    conditions, blocking, rows = [], [], []
    for q in questions:
        a = answers.get(q["id"], {"answer": "no", "evidence": "No answer given"})
        a = {**a, "answer": normalise(a["answer"])}
        credit = CREDIT[a["answer"]]
        got += credit * q["weight"]
        total += q["weight"]
        rows.append({**q, **a})
        if q.get("must_have") and a["answer"] != "yes":
            (blocking if a["answer"] == "no" else conditions).append(f"{q['id']} {q['area']}: {a['evidence']}")
    open_serious = [f for f in vendor.get("pentest", {}).get("findings", [])
                    if f["status"] != "fixed" and f["severity"] in ("critical", "high")]
    conditions += [f"{f['id']} open {f['severity']} pen-test finding: {f['title']}" for f in open_serious]
    score = round(100 * got / total, 1) if total else 0.0
    if blocking or score < 60:
        decision = "reject"
    elif conditions or score < 80:
        decision = "approve_with_conditions"
    else:
        decision = "approve"
    return {"score": score, "decision": decision, "conditions": conditions, "blocking": blocking, "rows": rows,
            "open_serious_findings": open_serious}


def render(vendor, result):
    label = {"approve": "Approve", "approve_with_conditions": "Approve with conditions", "reject": "Reject"}[result["decision"]]
    lines = [f"# Supplier security assessment: {vendor['supplier']}", "",
             f"Service: {vendor['service']}. Data: {vendor['data']}. Users: {vendor['users']}.",
             "All names and answers are fictional; this is a worked example of the method.", "",
             f"**Score: {result['score']:.0f}/100. Recommendation: {label}.**", ""]
    if result["blocking"]:
        lines += ["## Blocking issues", *[f"- {b}" for b in result["blocking"]], ""]
    if result["conditions"]:
        lines += ["## Conditions before go-live", *[f"- {c}" for c in result["conditions"]], ""]
    lines += ["## Answers", "| Q | Area | Weight | Answer | Evidence | Maps to |", "|---|---|---|---|---|---|"]
    lines += [f"| {r['id']} | {r['area']}{' (must have)' if r.get('must_have') else ''} | {r['weight']} | {r['answer']} | "
              f"{r['evidence']} | {', '.join(r['maps'])} |" for r in result["rows"]]
    pt = vendor.get("pentest")
    if pt:
        lines += ["", f"## Penetration test summary ({pt['date']})", "| Finding | Severity | Status |", "|---|---|---|"]
        lines += [f"| {f['id']} {f['title']} | {f['severity']} | {f['status']} |" for f in pt["findings"]]
    lines += ["", "## Ongoing monitoring (ISO 27001 5.22)",
              "- Re-assess yearly or on a major change, and when a new pen test is issued.",
              "- Track open conditions in the risk register with an owner and a date."]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    vpath = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "vendor" / "example_vendor.yaml"
    questions = yaml.safe_load((ROOT / "vendor" / "questions.yaml").read_text(encoding="utf-8"))
    vendor = yaml.safe_load(vpath.read_text(encoding="utf-8"))
    result = assess(questions, vendor)
    out = ROOT / "vendor" / "assessment_report.md"
    out.write_text(render(vendor, result), encoding="utf-8")
    print(f"{result['score']}/100 -> {result['decision']} ({len(result['conditions'])} conditions, {len(result['blocking'])} blocking)")
