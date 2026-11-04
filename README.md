# security-controls-metrics

[![ci](https://github.com/suhaibkhan916/security-controls-metrics/actions/workflows/ci.yml/badge.svg)](https://github.com/suhaibkhan916/security-controls-metrics/actions/workflows/ci.yml)

Measuring whether security controls actually work, and reporting it in a form a CISO or risk committee can act on. One Debian server is built twice, misconfigured and then hardened and patched, and measured with real tools. A second part is a worked supplier risk assessment.

Built for: security teams that must show control effectiveness (a security metrics programme, Cyber Essentials, ISO 27001) and manage risk from third-party services.

## What it does

| Part | How | Output |
|---|---|---|
| Control checks | 12 checks run inside the server, each mapped to **Cyber Essentials**, **CIS Controls v8**, **NIST CSF 2.0** and **ISO/IEC 27001:2022 Annex A** (`checks/controls.yaml`) | pass rate, severity-weighted score, by Cyber Essentials theme |
| Hardening benchmark | **Lynis** system audit | hardening index, warnings |
| Vulnerability exposure | **Trivy** image scan | counts by severity, fixable vs no fix released |
| Remediation performance | tracker of fix tickets (**synthetic**, seeded) | mean time to fix, SLA compliance, overdue by owner |
| Report | `metrics/report.py` | [`reports/security_metrics_report.md`](reports/security_metrics_report.md) |
| Supplier assessment | 10 weighted questions mapped to ISO 27001 5.19 to 5.23 and UK GDPR Art 28, plus a pen-test summary review | [`vendor/assessment_report.md`](vendor/assessment_report.md) |

## Results (collected 4 Nov 2026)

| Measure | Baseline | Hardened and patched |
|---|---|---|
| Controls passed | 0 / 12 | 12 / 12 |
| Lynis hardening index / warnings | 56 / 5 | 57 / 1 |
| Vulnerabilities (critical / high) | 478 (6 / 82) | 357 (4 / 52) |
| Fixable vulnerabilities outstanding | 120 | 0 |

What the numbers say:
- **Patching removed every fixable vulnerability, but 357 remain with no fix released.** Patch compliance and residual exposure are different measures; the second needs a risk decision (accept with an expiry, remove the package, restrict access), not a patch.
- **The generic benchmark barely moved while every targeted control was fixed.** Many Lynis tests (kernel, boot, running services) do not apply inside a container. One headline score is not enough; measure the controls that matter to the organisation.
- The synthetic remediation tracker shows high-severity fixes within 14 days only 37.5% of the time, against the Cyber Essentials 14-day rule. The report turns that into named, overdue tickets per owner.
- Supplier example: 78/100, approve with conditions (enforce MFA for supplier admins, breach notice under 24 hours, fix an open high pen-test finding).

## Run it

Needs Docker and Python 3.10+.

```bash
pip install -r requirements.txt
python run_all.py
```

That builds both images, runs the checks, Lynis and Trivy, then writes `results/`, the metrics report and the supplier report. Tests: `pytest -q` (17 tests, no Docker needed). CI runs the tests and the full collection on every push and keeps the reports as an artifact.

## What broke and how it was fixed

- **Removing the rogue UID 0 account failed** with `userdel` exit code 8 ("user currently logged in"): the account shares UID 0 with root, which runs the build. `userdel -f` removes it; the check `CTL-04` confirms only root has UID 0.
- **Supplier answers broke the scorer.** YAML 1.1 reads an unquoted `yes` or `no` as a boolean, so `answer: yes` arrived as `True`. Answers are now quoted and `normalise()` accepts both, with a test for each form.
- **A test passed for the wrong reason.** An assertion with an `or` escape hatch would accept any outcome. Rewritten to state the exact score and decision.
- **The Trivy JSON has no vulnerability-database date** in this version, so that field was dropped rather than reported as empty.

## Honest limitations

- One server, two snapshots. A real programme tracks an estate monthly; the method is the same, the trend matters more than one comparison.
- Firewall (`CTL-11`) and audit logging (`CTL-12`) check configuration files: containers do not load nftables or run auditd.
- The Cyber Essentials malware protection theme is not measured.
- Remediation tickets and the supplier are synthetic or fictional and illustrate the method, not a real organisation.
- Trivy scans OS packages only; vulnerability counts change as the database updates, so reruns will differ slightly.

See [docs/DESIGN_NOTES.md](docs/DESIGN_NOTES.md) for the reasoning behind each choice.

MIT licence.
