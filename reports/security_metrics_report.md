# Security controls effectiveness report

Scope: one Debian server (lab target), baseline vs hardened and patched. Report date 2026-10-31.
Remediation figures use SYNTHETIC (data/generate_tracker.py, seed 2026) data; control, Lynis and vulnerability figures are real tool output.

## Summary
- Control pass rate rose from **0%** to **100%** (12/12 controls).
- Fixable vulnerabilities outstanding fell from **120** to **0** (100.0% remediated).
- **357** vulnerabilities remain with no fix released (56 critical or high): these need a risk decision, not a patch.
- Lynis hardening index moved only 56 to 57 while warnings fell 5 to 1: a generic benchmark score is not a substitute for control-level measures.

## Key measures
| Measure | Baseline | Current |
|---|---|---|
| Controls passed | 0/12 | 12/12 |
| Weighted control score (high=3, medium=2, low=1) | 0% | 100% |
| High-severity control failures | 6 | 0 |
| Vulnerabilities, critical / high | 6 / 82 | 4 / 52 |
| Fixable vulnerabilities outstanding | 120 | 0 |
| Lynis hardening index / warnings | 56 / 5 | 57 / 1 |

## Cyber Essentials themes (current)
| Theme | Passed |
|---|---|
| Firewalls | 1/1 |
| Secure configuration | 6/6 |
| Security update management | 1/1 |
| User access control | 4/4 |

## Remediation performance (synthetic tracker)
| Severity | SLA | Tickets | Open | Mean days to fix | Within SLA | Open and overdue |
|---|---|---|---|---|---|---|
| critical | 14 days | 4 | 0 | 13.0 | 50.0% | 0 |
| high | 14 days | 12 | 6 | 18.3 | 37.5% | 2 |
| medium | 30 days | 18 | 10 | 21.2 | 54.5% | 3 |
| low | 90 days | 10 | 9 | 50.0 | 100.0% | 0 |

## Recommendations
1. Critical remediation within 14 days is 50.0% against a 90% target; Cyber Essentials requires high-risk and critical updates within 14 days.
2. High remediation within 14 days is 37.5% against a 90% target; Cyber Essentials requires high-risk and critical updates within 14 days.
3. Chase overdue critical and high tickets with their owners: Customer Systems (VUL-014); Data Platform (VUL-013).
4. Record a risk decision for the 357 unfixable vulnerabilities: accept with an expiry date, reduce exposure (remove the package, restrict network access), and re-scan when fixes ship.
5. Track these measures monthly; one snapshot shows a change, a trend shows whether controls are holding.

## Method and limits
- Controls: 12 checks in checks/controls.yaml, each mapped to Cyber Essentials, CIS Controls v8, NIST CSF 2.0 and ISO/IEC 27001:2022 Annex A.
- Lynis 3.0.8 system audit inside a container: kernel, boot and service checks do not apply there, which limits the index.
- Trivy 0.57.1 image scan, OS packages only.
- Firewall and audit controls check configuration files; containers do not load nftables or run auditd.
- The Cyber Essentials malware protection theme is not measured: an anti-malware agent does not run meaningfully in this container.
- Remediation figures are synthetic and illustrate the method, not a real organisation.
