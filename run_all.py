"""Build both target states, collect evidence, compute metrics, write both reports.

usage: python run_all.py        (needs Docker; about 5 minutes the first time while images download)
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def run(*args):
    print("+", " ".join(args))
    subprocess.run(args, cwd=ROOT, check=True)


if __name__ == "__main__":
    for state in ("baseline", "hardened"):
        run("docker", "build", "-q", "-f", "target/Dockerfile", "--target", state, "-t", f"scm-target:{state}", "target")
    for state in ("baseline", "hardened"):
        run(sys.executable, "scripts/collect.py", state)
    run(sys.executable, "metrics/compute.py")
    run(sys.executable, "metrics/report.py")
    run(sys.executable, "vendor/assess.py")
    print("Reports: reports/security_metrics_report.md and vendor/assessment_report.md")
