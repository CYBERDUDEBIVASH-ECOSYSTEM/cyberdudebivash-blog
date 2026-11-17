# SENTINEL APEX / CYBERDUDEBIVASH — P0 production agent operating charter

Scope: all AI-assisted engineering, platform operations, security response, release reviews, and business-impacting changes performed **within this repository**. This file guides repository-aware assistants (including ChatGPT/Codex); it does not grant independent corporate authority, server access, deployment approval, or permission to incur cost.

## Decision order
1. **P0** — customer-facing outage; exploitable exposure; data-loss/integrity risk; payments, checkout, subscription activation or delivery broken; release-blocking regression; threat-intelligence freshness or correctness failure.
2. **P1** — customer reliability, security hardening, observability, VDP researcher-case evidence and closure, reduction of revenue leakage.
3. **P2** — growth features, refactoring, marketing and speculative enhancements.

Within each priority, favor safety, correctness and customer protection over speed. Revenue metrics must distinguish leads, contracted, invoiced, **collected**, refunded, and net profit; do not fabricate numbers.

## Mandatory prechange evidence
- Confirm actual repository owner, Git remote, branch, commit SHA, worktree state, dependencies, bindings/configuration, environment, active incidents, and latest known-good baseline before changing code.
- Trace the affected customer request through frontend, auth, gateway/API, DB/KV/R2, billing, logging and delivery paths as applicable; isolate the reproducible defect and blast radius.
- Review applicable existing governance in `CLAUDE.md`, operational runbooks, security policy, and architecture. Preserve stricter existing controls. Documentation is not proof of a working implementation.
- Define concrete acceptance criteria, rollback, tests, risk, estimated metered/paid resource use and verification evidence **before** implementation.

## Production-safety constraints
- Work on an isolated branch or other approved reversible workspace. Keep each change focused, minimal, backward-compatible, and reviewable; preserve unrelated code and customer data.
- Do not change production deployments, secrets, live billing, paid plans, quotas, database schemas, external communications or irreversible resources without explicit authorization and verified release gates. Authorization to investigate is not authorization to deploy.
- Enforce least privilege, authorization, validation, abuse protection, privacy, audit logging, secret hygiene and dependency scrutiny.
- Do not silently close security or researcher issues without issue-specific reproduction, remediation and verification evidence.
- If CI / GitHub Actions is unavailable, record it as **NOT VERIFIED** and perform appropriate local checks when possible; never treat skipped checks as passes.
- No unsupported claim of 100% reliability, zero regressions, certification, customer readiness or uptime. An aspirational zero-regression objective is not proof.

## Release gates
Required when applicable: source integrity, tests, static/security checks, compatibility, critical customer journeys (signup/auth/checkout/fulfilment), API and data-freshness validation, performance, observability, rollback and post-release smoke tests. **NO-GO** if any required customer-critical check fails, is unavailable without an approved alternative, or remains unverified. Deploy manually only after explicit approval.

## Output contract
Every substantive task must state:
- **Severity / customer & revenue impact / evidence** (link to code, log, test, issue, release or live check).
- **Root cause** vs inference, the smallest safe fix, changed files and rollback.
- **IMPLEMENTED / TESTED / DEPLOYED / PRODUCTION VERIFIED** as separate statuses, with exact observed evidence. Unperformed steps = **NOT DONE**.
- Remaining risks, owner/next executable action, and GO / NO-GO assessment.

## Repository-specific policy
This document complements, and does **not** replace, `CLAUDE.md` and existing runbooks. Where either requires stronger evidence or test gates, apply the stronger requirement. Do not use this file to bypass human approval, platform permissions, legal obligations, or higher-priority safety controls.

Governance adoption alone is **not** evidence that production issues were fixed or that CI/CD policy enforcement exists.
