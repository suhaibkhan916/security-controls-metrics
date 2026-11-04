# Design notes

## Why measure controls, not just run a benchmark
A benchmark score answers "how does this host compare with a generic checklist?". A control measure answers "is the thing we promised (no root SSH, patches within 14 days) actually true?". This lab shows the difference directly: every targeted control went from failing to passing while the Lynis index moved by one point. Use both, and say which is which.

## Control design
- Each control is one shell command with exit 0 meaning pass, so it can be re-run by anyone and gives the same answer.
- Each control carries four mappings (Cyber Essentials, CIS Controls v8, NIST CSF 2.0, ISO 27001:2022 Annex A). One measurement then serves several reporting needs: a Cyber Essentials self-assessment, an ISO 27001 internal audit, a NIST-style board summary.
- Severity weights (high 3, medium 2, low 1) stop a pile of low findings hiding one critical gap. The report shows the plain pass rate and the weighted score side by side.

## Vulnerability measures
- **Fixable outstanding** is the patch-management measure: it should be zero after each patch cycle.
- **No fix available** is residual risk: it cannot be patched today, so each one needs a recorded decision (accept until a date, reduce exposure, or remove the software).
- Counting only the total would make good patching look like failure (478 to 357 "still bad") and hide the real question.

## Remediation SLAs
- Critical and high within 14 days, matching the Cyber Essentials requirement for high-risk and critical updates. Medium 30 days and low 90 days are an example internal policy.
- An open ticket counts as a breach only once it is older than its SLA. Open tickets still inside their SLA are left out of the compliance figure, so new work does not drag the number down unfairly.
- The report names overdue critical and high tickets by owner, because a percentage alone does not tell anyone what to do on Monday.

## Supplier assessment
- Weighted questions, with **must-haves** for things that cannot be traded off for personal data: an Article 28 processor agreement, UK or EEA processing (or a valid transfer mechanism), SSO with MFA for admins, and prompt breach notification.
- A must-have answered "no" blocks approval; "partial" becomes a condition before go-live. Open high or critical pen-test findings also become conditions.
- Three outcomes (approve, approve with conditions, reject) match how procurement decisions are actually made; most suppliers land in the middle.
- Re-assessment yearly or on major change covers ISO 27001 5.22 (monitoring and review of supplier services).

## Reproducibility
- Both target images start from the same pinned Debian snapshot, so differences come only from the hardening script.
- The synthetic tracker is generated with a fixed seed.
- CI rebuilds everything and re-runs the scans on every push.

## Extending it
- **More hosts:** run `collect.py` against each image or host and aggregate in `compute.py`.
- **Monthly trend:** keep each month's `metrics.json` and chart the measures over time; trend is what tells a committee whether controls are holding.
- **New control:** add an entry to `checks/controls.yaml` with its command and mappings; a test checks every control is fully mapped.
