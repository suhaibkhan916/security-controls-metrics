"""Collect evidence from one target state: control checks, Lynis hardening index, Trivy vulnerabilities.

usage: python scripts/collect.py baseline|hardened

Writes results/<state>/{controls,lynis,trivy}.json. Every number in the metrics report comes from these
files, which come from the real tools. Needs Docker.
"""
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
TRIVY = "aquasec/trivy:0.57.1"


def sh(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace", **kw)


def run_controls(container):
    controls = yaml.safe_load((ROOT / "checks" / "controls.yaml").read_text(encoding="utf-8"))
    if any(c.get("needs_apt_update") for c in controls):
        sh(["docker", "exec", container, "apt-get", "update", "-qq"])
    results = []
    for c in controls:
        r = sh(["docker", "exec", container, "sh", "-c", c["check"]])
        results.append({k: c[k] for k in ("id", "name", "severity", "ce", "cis", "nist", "iso")} | {"passed": r.returncode == 0})
    return results


def run_lynis(container):
    """Lynis system audit. Returns the hardening index (0 to 100) and warning/suggestion counts."""
    r = sh(["docker", "exec", container, "lynis", "audit", "system", "--quick", "--no-colors"])
    out = r.stdout
    idx = re.search(r"Hardening index\s*:\s*(\d+)", out)
    warn = re.search(r"Warnings\s*\((\d+)\)", out)
    sugg = re.search(r"Suggestions\s*\((\d+)\)", out)
    return {"hardening_index": int(idx.group(1)) if idx else None,
            "warnings": int(warn.group(1)) if warn else 0,
            "suggestions": int(sugg.group(1)) if sugg else 0,
            "lynis_version": (re.search(r"Lynis ([\d.]+)", out) or [None, None])[1]}


def run_trivy(image):
    """Trivy image scan (OS packages). Returns counts by severity and the fixable count."""
    r = sh(["docker", "run", "--rm", "-v", "/var/run/docker.sock:/var/run/docker.sock",
            "-v", "scm-trivy-cache:/root/.cache", TRIVY, "image", "--quiet", "--format", "json",
            "--scanners", "vuln", image])
    if r.returncode != 0:
        raise RuntimeError(f"trivy failed: {r.stderr[-400:]}")
    data = json.loads(r.stdout)
    counts = {s: 0 for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")}
    fixable = 0
    for res in data.get("Results", []):
        for v in res.get("Vulnerabilities") or []:
            counts[v.get("Severity", "UNKNOWN")] = counts.get(v.get("Severity", "UNKNOWN"), 0) + 1
            fixable += bool(v.get("FixedVersion"))
    return {"by_severity": counts, "total": sum(counts.values()), "fixable": fixable, "scanner": TRIVY}


def main(state):
    image = f"scm-target:{state}"
    container = f"scm-{state}"
    out = ROOT / "results" / state
    out.mkdir(parents=True, exist_ok=True)
    sh(["docker", "rm", "-f", container])
    r = sh(["docker", "run", "-d", "--name", container, image])
    if r.returncode != 0:
        sys.exit(f"cannot start {image}: {r.stderr}")
    try:
        stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        controls = run_controls(container)
        (out / "controls.json").write_text(json.dumps({"collected_at": stamp, "image": image, "controls": controls}, indent=1), encoding="utf-8")
        lynis = run_lynis(container)
        (out / "lynis.json").write_text(json.dumps({"collected_at": stamp, "image": image, **lynis}, indent=1), encoding="utf-8")
    finally:
        sh(["docker", "rm", "-f", container])
    trivy = run_trivy(image)
    (out / "trivy.json").write_text(json.dumps({"collected_at": stamp, "image": image, **trivy}, indent=1), encoding="utf-8")
    passed = sum(c["passed"] for c in controls)
    print(f"{state}: controls {passed}/{len(controls)} | lynis {lynis['hardening_index']} | "
          f"vulns {trivy['total']} (critical {trivy['by_severity']['CRITICAL']}, high {trivy['by_severity']['HIGH']})")


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("baseline", "hardened"):
        sys.exit(__doc__)
    main(sys.argv[1])
