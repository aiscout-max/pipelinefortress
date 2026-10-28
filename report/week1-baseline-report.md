# Week 1: Baseline Pipeline and Vulnerability Report

**Project:** PipelineFortress (CAP-DSE-3W), individual track
**Repository:** https://github.com/aiscout-max/pipelinefortress
**Target:** OWASP Juice Shop 20.3.0 (upstream commit `717f5ef`)
**Evidence:** pipeline run [40650503905](https://github.com/aiscout-max/pipelinefortress/actions/runs/40650503905) (bootstrap) and [40651312341](https://github.com/aiscout-max/pipelinefortress/actions/runs/40651312341) (first run with the gate armed: 0 new findings, all six jobs green)

## 1. What was built

A single GitHub Actions workflow (`.github/workflows/pipeline.yml`) that runs on every push and pull request:

| Stage | Tool (pinned) | Duration | Output |
|---|---|---:|---|
| Build & unit test | Node 24, `npm ci` | 1m45s | 419 server tests: 417 pass, 0 fail, 2 skipped |
| SAST | Semgrep 1.182.1 | 37s | `semgrep.json` |
| Secrets | gitleaks 8.30.1 | 13s | `gitleaks.json` (values redacted) |
| SCA | Trivy 0.76.1 | 44s | `trivy-fs.json` |
| Security gate | `fortress.gate` | 13s | Pass/fail + job summary |
| Deploy (staging) | kind v0.33.0 | 4m00s | Juice Shop rolled out; smoke test returned `{"version":"20.3.0"}` |

The four scan stages run in parallel. **The developer gets the security verdict 61 seconds after pushing**, and the whole pipeline, including the staging deploy, finishes in 5m50s. That is compatible with the team's 30+ deploys a day.

## 2. Baseline findings

| Stage | Critical | High | Medium | Low | Total |
|---|---:|---:|---:|---:|---:|
| SAST | — | 27 | 34 | 4 | 65 |
| Secrets | — | 69 | — | — | 69 |
| SCA | 9 | 29 | 33 | 5 | 76 |
| **Total** | **9** | **125** | **67** | **9** | **210** |

### 2.1 SAST (Semgrep)

Rulesets: `p/javascript`, `p/typescript`, `p/nodejsscan`, plus one custom rule (`security/semgrep/custom-rules.yml`).

| Rule | Count | Weakness |
|---|---:|---|
| `node_nosqli_injection` | 17 | NoSQL injection (MarsDB queries built from request data) |
| `node_insecure_random_generator` | 13 | `Math.random()`. Many uses are probably not security-relevant (FP candidates for Week 3). |
| `express-check-directory-listing` | 5 | Directory listing enabled (CWE-548) |
| `express-res-sendfile` | 4 | Path built from user input (CWE-73) |
| `node_username` / `node_password` | 5 | Hard-coded credentials |
| SQL injection (custom + registry rule) | 4 | `routes/login.ts:34`, `routes/search.ts:23` (CWE-89) |
| Other (`node_md5`, eval, timing attack, hard-coded JWT secret) | 17 | |

The custom rule `pf-sequelize-raw-query-interpolation` found exactly the two known SQL injection sinks and nothing else. The registry rule `express-sequelize-injection` reports the same two lines. The LLM triage in Week 3 is expected to cluster these duplicates.

### 2.2 Secrets (gitleaks)

69 findings: 54 `generic-api-key`, 12 `jwt`, 3 `private-key`.

**62 of the 69 (90%) are in test code** (`test/`, `*.spec.ts`): fixture JWTs and dummy keys. Only 7 are in shipped code or IaC:

- `lib/insecurity.ts`: RSA private key used to sign every JWT (critical in a real system)
- `routes/login.ts`, `data/static/users.yml`, `frontend/src/app/faucet/faucet.component.ts`
- `terraform/networking.tf`, `infrastructure/terraform/networking.tf`: leaked cloud key challenge

The pipeline runs gitleaks with `--redact`, so no secret value appears in any log or artifact. That matters because artifacts of a public repository are downloadable by anyone with a GitHub account.

### 2.3 SCA (Trivy)

76 vulnerabilities in 25 packages. 67 have a fixed version available.

| Critical | Package | Installed → Fixed |
|---|---|---|
| CVE-2015-9235 (×2) | jsonwebtoken | 0.1.0 / 0.4.0 → 4.2.2 |
| CVE-2019-10744 | lodash | 2.4.2 → 4.17.12 |
| CVE-2023-46233, CVE-2026-71851 | crypto-js | 3.3.0 → 4.2.0 |
| CVE-2026-59873 | tar | 6.2.1 → 7.5.19 |
| CVE-2026-101894, CVE-2026-53486 | decompress | 4.2.1 → *no fix* |
| GHSA-5mrr-rgp6-x4gr | marsdb | 0.6.11 → *no fix* |

## 3. OWASP Top 10 (2021) mapping

| Category | Evidence from the baseline |
|---|---|
| A01 Broken Access Control | Directory listing (5), user-controlled `sendFile` paths (4) |
| A02 Cryptographic Failures | MD5 hashing, `Math.random()`, private signing key in source |
| A03 Injection | SQL injection (2 sinks), NoSQL injection (19), `eval` |
| A05 Security Misconfiguration | Directory listing; runtime evidence follows with ZAP in Week 2 |
| A06 Vulnerable and Outdated Components | 76 SCA findings, 9 critical |
| A07 Identification and Authentication Failures | Hard-coded credentials, `jsonwebtoken` 0.x (CVE-2015-9235 signature bypass) |
| A08 Software and Data Integrity Failures | Upstream ships no lockfile (fixed in this fork, see §5) |

## 4. Gate policy

Juice Shop is intentionally vulnerable. Gating on all 210 findings would keep the pipeline permanently red, and developers would learn to ignore it. So:

1. The 210 findings above are recorded once in `security/baselines/baseline.json`, which holds fingerprints only and no code or secrets.
2. Only **new** findings are evaluated, against `security/gate-policy.toml`:

| Stage | A new finding blocks when | Rationale |
|---|---|---|
| Secrets | any severity | A leaked credential cannot be un-leaked; it must be rotated |
| SAST | ≥ HIGH | Medium/low rules are noisy (see `Math.random`) |
| SCA | CRITICAL **and** a fix exists | Never fail a build that the developer cannot make green |

3. On pull requests, gitleaks also scans the PR's own commits. A secret added and deleted within the same PR still fails.

Fingerprints are built to survive unrelated edits. SAST uses the rule plus the content of the flagged line (not its line number). Secrets use the rule, the file and the occurrence index, so not even a hash of a secret is stored. SCA uses the CVE, package and version.

## 5. Hardening decisions taken in Week 1

- **Committed `package-lock.json`.** Upstream disables lockfiles, so every build could resolve different dependency versions. Committing the lockfile makes SCA results and image builds reproducible.
- **Pinned and verified tooling.** Every action is pinned to a commit SHA, and the repository setting *require SHA-pinned actions* is enabled. Scanner binaries are downloaded at a fixed version and checked against the release's SHA-256 checksums (`security/install-tools.sh`). No `curl | sh`.
- **Pinned runner image** (`ubuntu-24.04`), ahead of GitHub's `ubuntu-latest` migration.
- **Least-privilege workflow token** (`permissions: contents: read`).
- **Local guardrails.** `.env` is excluded from git and from the Docker build context, and a gitleaks pre-commit hook blocks staged secrets.

## 6. Known gaps (carried into Week 2)

- **Runtime evidence:** this week's deploy only proves the app starts. The ZAP baseline scan against the kind deployment adds runtime findings in Week 2.
- **Frontend lockfile:** `npm install --package-lock-only` crashes locally (npm internal error), so CI resolves it on the fly. Frontend SCA results can therefore drift until it is committed.
- **Vulnerability DB drift:** a newly published critical CVE in an existing dependency appears as "new" and blocks PRs. This is intended, but it should be called out in the developer runbook.
- **IaC and container image** are not scanned yet (Checkov, Trivy image, Syft SBOM in Week 2).
