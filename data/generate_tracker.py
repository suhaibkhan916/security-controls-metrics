"""Generate the SYNTHETIC remediation tracker used for the time-to-fix metrics.

Real tickets are confidential, so this lab uses generated ones. The seed is fixed, so the CSV is
reproducible and the report can be regenerated exactly. Nothing in it describes a real organisation.

usage: python data/generate_tracker.py > data/remediation_tracker.csv
"""
import csv
import random
import sys
from datetime import date, timedelta

SEED = 2026
START = date(2026, 9, 1)
# (severity, number of tickets, typical days to fix low..high)
PROFILE = [("critical", 4, (2, 20)), ("high", 12, (3, 40)), ("medium", 18, (7, 75)), ("low", 10, (10, 120))]
OWNERS = ["Infrastructure", "Web Services", "Identity", "Data Platform", "Customer Systems"]
SOURCES = ["Vulnerability scan", "Penetration test", "MDR alert", "Supplier advisory"]


def rows():
    rnd = random.Random(SEED)
    n = 0
    for severity, count, (lo, hi) in PROFILE:
        for _ in range(count):
            n += 1
            opened = START + timedelta(days=rnd.randint(0, 55))
            days = rnd.randint(lo, hi)
            closed = opened + timedelta(days=days)
            still_open = closed > date(2026, 10, 31)
            yield {"ticket": f"VUL-{n:03d}", "severity": severity, "source": rnd.choice(SOURCES),
                   "owner": rnd.choice(OWNERS), "opened": opened.isoformat(),
                   "closed": "" if still_open else closed.isoformat()}


if __name__ == "__main__":
    w = csv.DictWriter(sys.stdout, fieldnames=["ticket", "severity", "source", "owner", "opened", "closed"], lineterminator="\n")
    w.writeheader()
    w.writerows(rows())
