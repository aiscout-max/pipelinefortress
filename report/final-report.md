# PipelineFortress: Secure CI/CD with GenAI-Assisted Triage

**Final report.** Capstone CAP-DSE-3W, PG Certificate in AI/GenAI Powered Cybersecurity, IIT Roorkee × Futurense
**Student:** Siddhesh · **Track:** DevSecOps Essentials, individual
**Repository:** https://github.com/aiscout-max/pipelinefortress
**Detailed weekly reports:** [Week 1 baseline](week1-baseline-report.md) · [Week 2 shift-left](week2-shift-left-report.md)

---

## 1. Executive summary

An e-commerce team ships 30+ times a day, and its security review sits at the end of each sprint. The CISO asked for a shift-left pipeline that catches 80% of vulnerabilities before merge and gives developers fast, usable feedback. This project builds that pipeline around OWASP Juice Shop and adds a GenAI triage assistant that never sends secrets or source code to the model.

| Goal | Result |
|---|---|
| Catch ≥ 80% before merge | **82%** (9 of 11 seeded weaknesses). 8 of 11 blocked after one policy fix the experiment itself exposed |
| Developer feedback time | Security verdict **70 s** after push; full pipeline with a real deployment and DAST in **9½ min** |
| Five security stages with sensible gates | Six stages (secrets, SAST, SCA, IaC, container, DAST); gates block only on *new* findings above per-stage thresholds |
| Hardened container + SBOM | Distroless, non-root, digest-pinned image; read-only root filesystem; default-deny network; restricted Pod Security; CycloneDX and SPDX SBOMs |
| No secrets or code reach the LLM | Five-layer redaction with fail-closed guard; canary tests for 9 secret and code shapes and 4 identifier types; every outbound payload audited and scanned with gitleaks (0 findings) |
| No hallucinated CVEs | Every model answer validated against scanner data: **0 invented identifiers or versions** in the 20 answered suggestions |
| Honest FP/FN analysis | Recall on real issues 1.0, precision 0.63; the model flagged no false positive (§7) |

The most useful results were the ones that went wrong and were caught: a container policy that let 4,452 new vulnerabilities through, a remediation tool that tried to open PRs on the upstream OWASP repository, and a version validator that silently skipped half its input. Each was found by a test, an experiment or a verification step, and each is fixed and documented.

## 2. Architecture

```
push / pull request
│
├─ Build & unit test (npm ci, 419 server tests)
├─ Secrets (gitleaks) ─┐
├─ SAST (Semgrep)      ├─▶ Security gate (pre-build) ──▶ verdict at ~70 s
├─ SCA (Trivy fs)      │
├─ IaC (Checkov)  ─────┘
│                         ▼
│   Image: build → Trivy image scan → Syft SBOM → container gate
│                         ▼
│   Deploy: kind cluster → smoke test → ZAP baseline → DAST gate
│                         ▼
└─ Consolidate: all findings → baseline candidate → metrics dashboard

On demand (human-triggered, master only):
  GenAI triage (read-only) → redaction → LLM → validation → report + audit log
                             (OpenRouter first, Gemini fallback)
  Remediation (write) → deterministic patch → scanner re-run → draft PR → human review
```

**Design rules held throughout:**

1. **Gate on new, not on everything.** Known findings are fingerprinted into a baseline (no code, no secret values), and only regressions block. Juice Shop is intentionally vulnerable; a pipeline that is always red teaches developers to ignore it.
2. **Policy as code.** Thresholds live in `security/gate-policy.toml` and custom Checkov policies in `policies/checkov/`, so every change to them is reviewed like code.
3. **Minimise data at ingestion.** The normaliser drops snippets, secret values and request/response evidence before anything else sees the findings.
4. **Pin and verify the supply chain.** Actions are pinned by SHA (and the repository requires it), scanner binaries are checksum-verified, base images are pinned by digest, and the lockfile is committed.
5. **Code decides, the model explains.** Clustering, eligibility, versions and patches are deterministic. The model contributes judgement and prose, and every claim it makes is checked.

## 3. Week 1: baseline pipeline

The baseline pipeline built, tested (417 of 419 server tests pass, 2 skipped) and deployed Juice Shop to an ephemeral kind cluster, with SAST, SCA and secrets stages. The first run produced 210 findings (9 critical, 125 high). 62 of the 69 secrets were in test code, the first sign of how much volume is noise. Upstream ships no lockfile, so SCA results changed run to run; committing `package-lock.json` made them reproducible. Details: [Week 1 report](week1-baseline-report.md).

## 4. Week 2: shift-left coverage and hardening

IaC, container, SBOM and DAST stages were added: 365 findings across six stages, none of the IaC failures in files this project owns. Hardening was proven, not assumed:

- **Read-only root filesystem.** The first attempt crash-looped (`EROFS`). Searching the server code for every write path led to an init container that seeds only those directories. The control was not disabled.
- **Default-deny NetworkPolicy.** Startup logs show the app failing to reach external domains, so egress really is blocked.
- **Restricted Pod Security Standard,** enforced by the API server, plus a custom Checkov rule that requires it on every namespace.

Details and evidence: [Week 2 report](week2-shift-left-report.md).

## 5. Metrics that answer the CISO's question

The dashboard (`fortress/dashboard.py`, rendered on every run) leads with one number: **seeded weaknesses caught before merge**.

| Seeded weakness | Caught by | Blocked |
|---|---|---|
| Hard-coded key; key added then deleted | Secrets | ✔ ✔ |
| SQL injection; TLS verification off | SAST | ✔ ✔ |
| JWT accepts `alg: none` | — (missed) | ✘ |
| Vulnerable direct dependency | SCA | ✔ |
| Privileged container; NodePort service (custom policy) | IaC | ✔ ✔ |
| Full Debian instead of distroless | Container | ✘ → ✔ after the policy fix |
| Insecure cookie | DAST | (LOW, by design) |
| Unauthenticated admin endpoint | — (missed, expected) | ✘ |

A documentation-only control PR showed no run-to-run noise. The container miss was a policy gap: 4,452 new findings, none "critical with a fix", so nothing tripped the gate. A per-stage regression budget (`max_new = 50`) now blocks it, which a re-run proved. Other metrics on the dashboard are chosen for actionability: feedback time, new blocking findings, noise sources (90% of secrets in tests, 68% of container findings duplicating SCA), and the share of dependency findings with a fix available (71%).

## 6. GenAI triage

### 6.1 Redaction layer: what may leave the runner

`fortress/redact.py` is the only path from findings to the model. It has five independent defences:

| # | Defence | Proof |
|---|---|---|
| 1 | **Ingestion minimisation.** The normaliser never copies snippets, secret values or ZAP evidence | Unit tests on fake keys, SQL and cookies |
| 2 | **Allowlist.** Outbound views are rebuilt from fixed fields only | Canary fields (`snippet`, `evidence`, `secret`) never appear |
| 3 | **Secrets never sent.** Secret clusters get fixed advice ("revoke, rotate, purge history, use a secret store") and are not sent to the model | 68 clusters withheld on real data |
| 4 | **Pseudonymisation.** Paths, e-mails, URLs, hosts and IPs become `PATH_n`, `EMAIL_n`, … with the mapping kept on the runner | Audit logs contain 0 real paths |
| 5 | **Fail-closed guard.** Every outbound string is scanned for secret shapes, high-entropy tokens and code; any hit means the batch is not sent | 9 canary types × every field; no false positive on the 296 real findings |

**Verification:** every payload that leaves is written byte-for-byte to an audit directory, and `triage.yml` runs gitleaks over that directory and fails if it finds anything. On the real runs, gitleaks reported **no leaks**.

The tests caught four bugs in the guard before it shipped. One example: the guard read JSON braces as source code and blocked clean payloads. The pre-commit hook then blocked the commit of the canary tests themselves, which is defence in depth working on its own author. The canaries now live in the gitleaks-allowlisted fixtures directory.

### 6.2 Triage engine

`fortress/triage.py` works in four steps:

1. **Clusters duplicates** deterministically, per package for dependencies (one upgrade fixes all of a package's CVEs, in the lockfile and the image alike), per line for SAST, and across the duplicated Terraform trees. 365 findings become 196 clusters.
2. **Chooses what the model sees** round-robin by stage. A first version sent only dependency clusters, because they dominate by severity, so the model never judged the SAST findings where false positives live.
3. **Calls the model** in batches of 10, at temperature 0 with a strict JSON response schema, with backoff on 429/5xx and timeouts. Providers are tried in order: OpenRouter (`nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free`) first, then Gemini (`gemini-flash-latest`). Both receive the identical redacted payload, and the report records which model answered each cluster. The scored runs in §7 used Gemini alone; the fallback chain was added afterwards because of the outages described there.
4. **Validates every answer:** 3 to 5 fix lines, priority 1 to 10, and no CVE/GHSA identifier or version the scanners did not report. A failed check rejects the suggestion and marks the cluster for human triage. A failed model call does the same, so the tool never guesses.

The system prompt is versioned in the prompt library (`fortress/prompts/`), which also records its design rules and results.

### 6.3 Remediation PRs

`fortress/remediate.py` turns the top triaged dependency clusters into draft PRs:

- The **target version comes from the scanner**: the lowest single version that fixes every fixable CVE in the package, never a downgrade. It never comes from model text.
- Direct dependencies are bumped; transitive ones are pinned through npm `overrides`.
- **Trivy re-scans the patched lockfile before a PR is opened.** This check refused a `jsonwebtoken` 0.4.0 → 9.0.0 bump: the CVEs stayed, because `express-jwt` keeps its own nested copy. No PR was opened for it.
- PRs are drafts labelled `ai-generated`, with the model's validated rationale and fix lines and a reviewer checklist. A human must approve.

**Incident:** the first real remediation run called `gh pr create` without `--repo`. In a fork, `gh` resolves to the upstream parent, so the tool tried to open AI-generated PRs on `juice-shop/juice-shop`. It failed only because the base branch did not exist there; nothing was created upstream (verified). The tool now refuses to run without an explicit repository, and both workflows pin `GH_REPO`. This is the blast-radius risk of AI-driven automation in a small, concrete form.

## 7. Honest evaluation of the LLM triage

### 7.1 Method

Ground truth for the 30 clusters the model judged is in `metrics/triage-labels.json`. Each label carries code or lockfile evidence, verified by grep (for example "decompress is reachable only through `download()` without `extract`"; "`findOne` here is Sequelize, which parameterises"). The result: 18 real, 11 false positive, 1 uncertain. Positive class = *real issue*; the model predicts *real* unless it sets `likely_false_positive`.

### 7.2 Results

Two real runs were attempted on the Phase 2 findings. Each sent 30 clusters in three batches of 10.
In **both** runs, batch 2 never got an answer: HTTP 503 "high demand" and stalled reads through every
retry in run 1, and no answer for over half an hour in run 2, which was then stopped. Those 10 clusters
went to human triage, as designed. The scored results come from run 1 (`metrics/triage-run1.json`,
`metrics/triage-eval-run1.json`).

| Validation (run 1) | |
|---|---:|
| Clusters answered | 20 of 30 |
| Suggestions accepted | 20 |
| Rejected by validation | 0 |
| Invented CVE/GHSA identifiers | **0** |
| Invented versions | **0** |

| Confusion (19 scored; C003 labelled uncertain) | Model: real | Model: false positive |
|---|---:|---:|
| **Truly real** | TP = 12 | FN = **0** |
| **Truly false positive** | FP = 7 | TN = 0 |

| Metric | Value |
|---|---:|
| Recall on real issues | **1.00** |
| Precision | 0.63 |
| False positives the model flagged ("noise caught") | **0 of 7** |
| Mean priority: real / false positive (1 = fix first) | 4.0 / 4.6 |

The seven false positives the model accepted as real were: `tar` (build tooling only), `crypto-js` (only inside
pdfkit's unused PDF encryption), `moment` (a private copy, no user-controlled parsing), three Sequelize
`findOne` calls reported as NoSQL injection, and ZAP's "Dangerous JS Functions" in the minified bundle
(although the model did give that one the lowest priority, 9).

Not scored, because batch 2 failed: C005 `decompress` (fp), C006 `marsdb` (real), C007 `sanitize-html` (real),
C008 `minimatch` (fp), C088 profile XSS (real), C089 reviews `$where` (real), C116/C117 HTTP load balancer
(real), C153 CORS (real), C186 COEP (real).

**After the scored runs.** OpenRouter was added as the primary provider, with Gemini as fallback. A demonstration run
on a 135-finding set (131 clusters) got answers for all 30 clusters sent, from the OpenRouter model, with 30 accepted,
0 rejected and 0 invented identifiers; 69 secret clusters were withheld. That run is **not scored**: the ground-truth
labels belong to the Phase 2 clusters, so it shows availability and validation, not accuracy.

### 7.3 What the numbers mean

- **The model is safe but does not reduce noise.** It never dismissed a real issue, so a team could not lose a true positive by trusting it. But it also never identified a false positive, so it did not reduce the volume a human must review.
- **Privacy versus context.** The misses are the same kind of finding every time: build-time-only dependencies (`tar` under sqlite3's build tooling), unreachable code paths (`decompress` without `extract`, `crypto-js` inside pdfkit's unused encryption), and an ORM mistaken for a MongoDB driver. Each needs either the code or the dependency graph to judge, and the redaction layer removes exactly that context by design. The finding is a trade-off, not a bug: the same design that guarantees no source code leaves the runner also guarantees the model cannot do reachability analysis.
- **Where to go next without weakening redaction:** compute context features on the runner and send labels, not code. Examples: `runtime_reachable: false` from the lockfile's dependency chain; `data_layer: sequelize` from imports; `location: test` from the path class. Each is a fact the guard can check, carries no proprietary content, and directly targets the observed false positives.
- **Prioritisation is weak.** Mean priority given to real issues (4.0) and to false positives (4.6) barely differs. The deterministic pre-ranking (severity, fix available, occurrences) did most of the ordering.
- **Hallucination control worked.** No invented CVE or version was accepted. The schema plus validator design means a hallucination costs one rejected suggestion, never a wrong recommendation.
- **Availability is a real operational risk.** The free tier answered HTTP 503 "high demand" and stalled reads during the runs; the same batch of 10 clusters failed in both real runs. The pipeline degrades to human triage rather than failing or guessing. A second provider now sits behind the same validator (§6.2); a production setup still needs a paid tier, because both providers here are free.

## 8. Sample remediation PRs and review notes

`fortress.remediate` (run 1 triage, `--max-prs 3`) opened three draft PRs, each re-scanned by Trivy before opening.
A fourth candidate, `jsonwebtoken` 0.4.0 → 9.0.0, was **refused by the tool**: after the bump Trivy still reported its CVEs,
because `express-jwt` 0.1.3 carries its own nested copy.

| PR | Change | CVEs fixed (Trivy re-scan) | Full pipeline on the PR | Verdict |
|---|---|---:|---|---|
| [#15](https://github.com/aiscout-max/pipelinefortress/pull/15) | `jws` 0.2.6 → 3.2.3 (npm override) | 2 | ✘ **Build & unit test failed**: 14 JWT tests (`currentUser`, `isCustomer`, `isDeluxe`, JWT challenges) | Reject |
| [#16](https://github.com/aiscout-max/pipelinefortress/pull/16) | `lodash` → 4.18.0 (npm override) | 5 | ✔ All 9 jobs green ([run](https://github.com/aiscout-max/pipelinefortress/actions/runs/40966440289)) | Approve, with a check |
| [#17](https://github.com/aiscout-max/pipelinefortress/pull/17) | `moment` → 2.29.2 (npm override) | 3 | ✔ All 9 jobs green ([run](https://github.com/aiscout-max/pipelinefortress/actions/runs/40966460292)) | Approve |

**Two of three PRs are correct on first review.** The one that is not was caught by the pipeline's own tests, not by luck.

### Review notes

*Drafted with AI assistance from the pipeline evidence; reviewed and signed by Siddhesh, and posted on each PR ([#15](https://github.com/aiscout-max/pipelinefortress/pull/15#issuecomment-6542697384), [#16](https://github.com/aiscout-max/pipelinefortress/pull/16#issuecomment-6542697586), [#17](https://github.com/aiscout-max/pipelinefortress/pull/17#issuecomment-6542697835)).*

**#15 `jws` → 3.2.3. Reject.** The CVEs are real and reachable (forgeable tokens on every authenticated request), but an
override is the wrong tool here. `jsonwebtoken` 0.4.0 calls the jws 0.2 API, and jws 3.x changed `verify()`; 14 auth tests
fail. The correct fix is a coordinated upgrade of `jsonwebtoken` and `express-jwt`, with code changes in `lib/insecurity.ts`.
A human has to do that. Lesson: "the scanner no longer reports the CVE" is necessary but not sufficient, and the test stage
is what makes AI-proposed dependency changes safe to consider.

**#16 `lodash` → 4.18.0. Approve after one manual check.** Tests, gates, deploy and DAST are green and five CVEs are gone.
The override also replaces `sanitize-html` 1.4.2's private lodash 2.4.2 with 4.18.0, a major-version jump inside a security
control. The server tests do not exercise sanitisation deeply, so before merging, confirm that feedback and review input is
still sanitised: submit a known payload in staging and check the stored value.

**#17 `moment` → 2.29.2. Approve.** Backward-compatible upgrade, all green. Note for honesty: the ground-truth label for this
cluster is *false positive* (express-jwt's private copy never parses user-controlled strings), so the PR is low-risk hygiene,
not an urgent fix. The model rated it priority 4 because it had no reachability context (§7.3).

## 9. DevSecOps maturity self-assessment

Assessed against the OWASP DevSecOps Maturity Model (DSOMM), levels 1 (basic) to 4 (advanced), with evidence from this repository.

| Dimension | Sub-dimension | Level | Evidence | Gap to next level |
|---|---|---:|---|---|
| Build & deployment | Build | 3 | Pinned actions (enforced), checksum-verified tools, digest-pinned images, committed lockfile, SBOM on every build | Signed images and SLSA provenance (cosign) |
| | Deployment | 2 | Every PR deploys to an ephemeral, hardened kind cluster | Promotion to persistent environments, admission policy for signed images |
| | Patch management | 2 | Dependency CVEs triaged automatically; verified AI patch PRs | Scheduled automatic updates (Dependabot/Renovate) with the same verification |
| Culture & organisation | Process | 2 | Gates as policy as code; human approval for every AI change | Security champions, documented exception process with expiry dates |
| Implementation | Application hardening | 2 | Fixes proposed for dependencies; app is intentionally vulnerable | Systematic remediation of the baseline |
| | Infrastructure hardening | 3 | Read-only root filesystem, default-deny network, restricted PSS, non-root distroless, custom policies | Runtime detection (Falco), mTLS |
| Information gathering | Logging & metrics | 2 | Consolidated findings per run, catch rate, feedback time and noise metrics on a dashboard | Trend storage across runs, MTTR |
| Test & verification | Static depth | 3 | SAST (registry + custom rules), SCA, secrets (tree and PR history), IaC with custom policies | Reachability-aware SCA, more custom rules (e.g. JWT `alg: none`) |
| | Dynamic depth | 1 | Passive ZAP baseline | Authenticated, API-aware active scanning in staging |
| | Consolidation | 3 | One normalised schema; baseline-aware gate; clustering; GenAI triage with validation | Ticketing integration, SLA tracking |

**Overall: level 2, with level 3 in build, infrastructure hardening, static testing and consolidation.** The weakest area is dynamic testing: a passive scan of an SPA sees headers, not business logic, which is exactly why seed 11 was missed.

## 10. Ethics, responsible AI use and disclosure

- **Lab confinement.** All scanning ran against the ephemeral kind deployment inside GitHub-hosted runners, reached through `kubectl port-forward` on localhost. No external target was scanned. A custom policy keeps the staging service cluster-internal.
- **Data handling.** Secrets and source code never reached an LLM (§6.1, with audit evidence). The repository is public by the student's choice, so all scanner artifacts are redacted at source.
- **GenAI use, disclosed:**
  - **Triage models inside the product:** NVIDIA Nemotron (`nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free`, via the OpenRouter API) first, and **Google Gemini** (`gemini-flash-latest`, via API) as fallback. Gemini produced all scored results (§7) and the text in PRs #15–#17. The models rank and explain redacted findings and draft fix text. Every output is schema-validated against scanner data, and every resulting PR requires human approval. Free endpoints may retain prompts, which is acceptable only because nothing but the redacted, audited payload is sent.
  - **Anthropic Claude** (Claude Code, Claude Opus 5.5) was used as a development assistant to build the pipeline, tooling, tests and drafts of these reports. Its work was verified through 44 automated tests, linters (actionlint, shellcheck, Checkov), real pipeline runs linked as evidence, and the student's review of code, ground-truth labels and PRs.
- **Credential hygiene.** Both API keys (OpenRouter and Gemini) are stored only as GitHub Actions secrets and in a git-ignored local file, and neither was ever printed or committed (the gitleaks pre-commit hook and CI history scan both guard this). The Gemini key was once pasted into a chat during setup. Rotation was recommended; the student accepted the risk and kept it.

## 11. Limitations and future work

- **Detection gaps:** JWT `alg: none` (add a custom Semgrep rule), authorization flaws (authenticated DAST with an access-control matrix).
- **Triage context:** runner-computed reachability and location features (§7.3), then re-score with the same labels.
- **Model availability:** the second provider is in place; a paid tier is still needed for reliable service. Re-score with the OpenRouter model on the labelled Phase 2 clusters to compare the two models.
- **Remediation scope:** dependencies only. IaC fixes could follow the same pattern: deterministic patch, re-run Checkov, open the PR only if the check passes.
- **Stretch goals not done:** Falco runtime detection with a SIEM stub; a Checkov "policy bot" that explains failures in PRs.

## Appendix: evidence index

| Evidence | Where |
|---|---|
| Pipeline definition | `.github/workflows/pipeline.yml` |
| Gate policy, baseline, custom rules | `security/gate-policy.toml`, `security/baselines/baseline.json`, `security/semgrep/`, `policies/checkov/` |
| Hardened image and manifests | `Dockerfile`, `deploy/k8s/juice-shop.yaml` |
| Normaliser, gate, dashboard, redaction, triage, remediation | `fortress/` (44 tests in `fortress/tests/`) |
| Prompt library | `fortress/prompts/` |
| Seeded experiment | `metrics/seeds.json`, `metrics/seeded-results.json`, PRs #2–#14 |
| Triage runs, labels, scores | `metrics/triage-run*.json`, `metrics/triage-labels.json`, `metrics/triage-eval*.json` |
| AI remediation PRs | PRs #15–#17 (label `ai-generated`) |
