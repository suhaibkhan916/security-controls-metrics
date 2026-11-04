# Supplier security assessment: ExampleFeedback Ltd (fictional)

Service: Online feedback surveys for customers and staff. Data: Customer names, work email, customer ID, free-text feedback (may include special category data). Users: About 20,000 customers and 3,000 staff.
All names and answers are fictional; this is a worked example of the method.

**Score: 78/100. Recommendation: Approve with conditions.**

## Conditions before go-live
- Q04 Identity and access: SAML SSO supported; MFA optional for supplier admin accounts
- Q07 Incident management: Contract says 'within 72 hours'
- PT-1 open high pen-test finding: Stored cross-site scripting in survey comments

## Answers
| Q | Area | Weight | Answer | Evidence | Maps to |
|---|---|---|---|---|---|
| Q01 | Certification and assurance | 2 | partial | Cyber Essentials (basic), ISO 27001 certification planned for next year | ISO 5.19, ISO 5.21 |
| Q02 | Data protection (must have) | 3 | yes | Template DPA provided, Article 28 clauses present | UK GDPR Art 28, ISO 5.20 |
| Q03 | Data protection (must have) | 3 | yes | Hosted in a UK cloud region; support staff access from the UK only | UK GDPR Art 44-46, ISO 5.23 |
| Q04 | Identity and access (must have) | 3 | partial | SAML SSO supported; MFA optional for supplier admin accounts | ISO 5.17, ISO 8.5 |
| Q05 | Encryption | 2 | yes | TLS 1.2+, AES-256 at rest (provider managed keys) | ISO 8.24 |
| Q06 | Vulnerability management | 2 | yes | Annual test by a CREST member; summary provided (see pentest below) | ISO 8.8, ISO 5.22 |
| Q07 | Incident management (must have) | 3 | partial | Contract says 'within 72 hours' | UK GDPR Art 33(2), ISO 5.20, ISO 5.24 |
| Q08 | Supply chain | 2 | yes | Sub-processor list published; 30 days' notice of changes | UK GDPR Art 28(2), ISO 5.21 |
| Q09 | Resilience | 1 | no | Backups taken daily; restore not tested, no stated RTO | ISO 8.13, ISO 5.30 |
| Q10 | Exit | 2 | yes | CSV export; deletion within 30 days with certificate | ISO 5.20, ISO 8.10 |

## Penetration test summary (2026-06-15)
| Finding | Severity | Status |
|---|---|---|
| PT-1 Stored cross-site scripting in survey comments | high | open |
| PT-2 Session cookie missing SameSite attribute | medium | fixed |
| PT-3 Verbose error messages reveal framework version | low | open |
| PT-4 No account lockout on supplier admin login | high | fixed |

## Ongoing monitoring (ISO 27001 5.22)
- Re-assess yearly or on a major change, and when a new pen test is issued.
- Track open conditions in the risk register with an owner and a date.
