# Week 2: Shift-Left Coverage, Hardening and Metrics

**Project:** PipelineFortress (CAP-DSE-3W), individual track
**Repository:** https://github.com/aiscout-max/pipelinefortress
**Evidence:** PR [#1](https://github.com/aiscout-max/pipelinefortress/pull/1). Runs [40686064885](https://github.com/aiscout-max/pipelinefortress/actions/runs/40686064885) (first all-green six-stage run) and [40742362443](https://github.com/aiscout-max/pipelinefortress/actions/runs/40742362443) (all gates armed, plus the dashboard). Seeded PRs #2 to #14.

## 1. What was added

| Stage | Tool | Scope | Gate (new findings only) |
|---|---|---|---|
| IaC | Checkov 3.3.30 + 2 custom policies | Kubernetes, Dockerfiles, Terraform, GitHub workflows | any severity |
| Container | Trivy 0.76.1 image scan | OS packages + production `node_modules` in the built image | CRITICAL with a fix, **or more than 50 new** (§5.3) |
| SBOM | Syft 1.55.0 | CycloneDX 1.7 + SPDX JSON, published as a build artifact | — |
| DAST | OWASP ZAP 2.17.0 baseline (passive) | The kind staging deployment, via port-forward inside the runner | HIGH |

The pipeline now has nine jobs. The four pre-build scans run in parallel with the build. Image scanning, deployment and DAST run only after the pre-build gate passes.

| Job | Starts after push | Duration |
|---|---:|---:|
| Secrets, IaC, SAST, SCA (parallel) | 2s | 13s to 52s |
| Build & unit test | 2s | 2m 13s |
| **Security gate (pre-build)** | 57s | 13s, **verdict at 1m 10s** |
| Image scan & SBOM | 2m 17s | 3m 42s |
| Deploy to kind & DAST | 6m 01s | 3m 20s |
| Consolidate & dashboard | 9m 23s | 8s |

The developer hears about secrets, code, dependencies and IaC **70 seconds** after pushing. The full pipeline, including a real deployment and a DAST scan, finishes in **9m 31s**.

## 2. Hardening

### 2.1 Container image

- Both base images are pinned by digest (`node:24@sha256:…` builder, `distroless/nodejs24-debian13@sha256:…` runtime). A re-tagged upstream image cannot change the build silently.
- The runtime image is distroless and non-root (UID 65532), with no shell and no package manager. Seed 09 (§5) shows what this saves: the full Debian alternative carries 4,452 more known vulnerabilities.
- `HEALTHCHECK` uses the bundled Node runtime, because distroless has no `curl`.
- Checkov Dockerfile checks: **262 passed, 0 failed** on our Dockerfile.

### 2.2 Kubernetes

| Control | How | Evidence |
|---|---|---|
| Read-only root filesystem | An init container copies the directories Juice Shop rewrites (`frontend/dist`, `ftp`, `i18n`, `data`, `uploads`, `.well-known`) into an `emptyDir`; only those are mounted writable | The first attempt crash-looped with `EROFS … .well-known/csaf/provider-metadata.json`. The fix was found by searching the server code for every write path, not by disabling the control. |
| Default-deny network | `NetworkPolicy` denies all ingress and egress; one policy allows TCP 3000 in and DNS out | Startup logs show `Domain https://www.alchemy.com/ is not reachable`: egress really is blocked |
| Pod Security Admission | Namespace enforces the `restricted` Pod Security Standard | The API server would reject a privileged or root pod at deploy time, independently of Checkov |
| Least privilege | Non-root, `allowPrivilegeEscalation: false`, all capabilities dropped, `RuntimeDefault` seccomp, no service-account token, CPU and memory limits | Checkov Kubernetes: **90 passed, 0 failed** |

Two checks are skipped, each with a written reason in a `checkov.io/skip` annotation. `CKV_K8S_15` (pull policy `Always`) and `CKV_K8S_43` (image digest) both assume a registry, but the image is built and side-loaded into kind within the same job.

### 2.3 Policy as code

Built-in rules check each pod spec in isolation. Two custom Checkov policies (`policies/checkov/`) encode decisions specific to this platform:

| ID | Rule | Why built-ins are not enough |
|---|---|---|
| `CKV_PF_K8S_1` | Every Namespace must *enforce* the restricted Pod Security Standard | Moves enforcement into the API server, so a manifest that forgets a `securityContext` fails at deploy |
| `CKV_PF_K8S_2` | Services must be `ClusterIP` | The staging app is deliberately vulnerable and must never be reachable outside the lab |

Both were tested in both directions: they pass on the real manifests and fail on a crafted bad manifest. Seed 08 (§5) showed `CKV_PF_K8S_2` blocking a real PR.

## 3. New findings

| Stage | Total | Critical | High | Medium | Low | Info |
|---|---:|---:|---:|---:|---:|---:|
| IaC | 54 | — | — | 54 | — | — |
| Container | 98 | 9 | 27 | 51 | 11 | — |
| DAST | 9 | — | — | 2 | 4 | 3 |

(OSS Checkov reports no severity, so IaC findings are normalised to MEDIUM. The gate blocks any new IaC failure anyway.)

- **IaC:** none of the 54 failures is in a file this project owns. 50 are in Juice Shop's upstream AWS Terraform examples, which exist twice (`terraform/` and `infrastructure/terraform/`), and 4 are in test Dockerfiles. They are baselined. Our Kubernetes manifests, Dockerfile and workflows are clean.
- **Container:** 67 of the 98 are the same CVEs that SCA already reports for `package-lock.json`, now seen inside the image. The other 31 come from the Debian base layer. Dependency findings overall (SCA plus container) have a fix available for 120 of 168 (71%).
- **DAST:** Content Security Policy header not set, and a permissive cross-domain (CORS) configuration (both MEDIUM); missing COEP/COOP headers, deprecated `Feature-Policy`, and dangerous JS functions (LOW); three informational alerts. No HIGH alert, which is expected from a passive scan of an SPA.
- **SBOM:** 2,744 components, 740 of them packages with a purl (725 npm, 14 Debian).

## 4. Gate behaviour across runs

- **Per-stage bootstrap.** When IaC, container and DAST were added, they had no baseline entries, so they reported without blocking for one run, and their baseline was then committed. A new scanner therefore never breaks every open PR on its first run.
- **Stability.** Two consecutive full runs on the same code produced **0 new and 0 resolved** findings in all six stages. Trivy's database and ZAP's spider did not introduce drift in that window. The seeded experiment's control PR confirmed it again (§5).
- **SCA drift.** Between Week 1 and Week 2 the SCA count went from 76 to 70 on unchanged code. That came from the frontend lockfile resolved in CI and from Trivy database updates. It is the reason the experiment uses a control PR.

## 5. Seeded-vulnerability experiment

### 5.1 Method

Eleven draft PRs each introduced one weakness. A twelfth, documentation-only PR served as the control. The stage expected to catch each weakness was written down (`metrics/seeds.json`) **before** any run. `metrics/collect_seeded.py` reads each PR's run:

- **caught** means the stage reported findings absent from the baseline, minus any stage that also did so on the control PR;
- **blocked** means a gate failed the PR.

The control PR reported no new findings in any stage, so there was nothing to subtract. Seed commits bypassed the local pre-commit hook on purpose, because the experiment measures the CI layer. Without that bypass, the hook would have stopped seeds 01 and 02 on the developer's machine.

### 5.2 Results

| # | Seeded weakness | Expected | Caught by | Merge |
|---|---|---|---|---|
| 01 | Hard-coded API key in a new module | Secrets | Secrets | Blocked |
| 02 | Key committed, then deleted in the next commit | Secrets | Secrets (PR history scan) | Blocked |
| 03 | Raw SQL built from a URL parameter | SAST | SAST (custom + registry rule) | Blocked |
| 04 | TLS verification disabled process-wide | SAST | SAST | Blocked |
| 05 | JWT verification accepts `alg: none` | SAST | **Missed** | Not blocked |
| 06 | Direct dependency on minimist 1.2.5 | SCA | SCA | Blocked |
| 07 | Container runs privileged | IaC | IaC | Blocked |
| 08 | Service exposed as NodePort | IaC | IaC (custom policy) | Blocked |
| 09 | Runtime image switched to full Debian | Container | Container (4,452 new) | **Not blocked** |
| 10 | Cookie without HttpOnly or SameSite | DAST | DAST (2 LOW alerts) | Not blocked (below HIGH) |
| 11 | Admin export endpoint with no authorization | none | Missed (expected) | Not blocked |

**Caught before merge: 9 of 11 (82%), against the CISO's 80% target. Blocked: 7 of 11 (64%) with the original policy, 8 of 11 (73%) after the fix in §5.3.**

### 5.3 What the misses and non-blocks mean

- **Seed 05 is a real false negative.** None of the three Semgrep rulesets flags `jwt.verify(…, { algorithms: ['none', …] })`. Mitigation: a custom Semgrep rule, written the same way as `pf-sequelize-raw-query-interpolation`.
- **Seed 11 is outside what these tools can see.** Missing authorization on a new route is a business-logic flaw. Catching it needs authenticated DAST with an access-control matrix, or a code-review checklist. Reporting it honestly is the point of including it.
- **Seed 09 exposed a policy gap, which is now fixed.** The container gate blocked only on *critical vulnerabilities with a fix*. Swapping distroless for full Debian added 4,452 findings, none of them critical-with-fix, so the PR passed while the attack surface grew by two orders of magnitude. The gate now supports a per-stage **regression budget** (`max_new`). The container stage blocks on more than 50 new findings, whatever their severity. Re-test: [PR #14](https://github.com/aiscout-max/pipelinefortress/pull/14) (seed 09b) against the new gate: the *Image scan & SBOM* job failed with "Regression budget exceeded: 4452 new container findings (budget 50)", and the deploy was skipped ([run](https://github.com/aiscout-max/pipelinefortress/actions/runs/40747119278)). With the budget in place, **8 of 11 seeds are blocked (73%)**.
- **Seed 10 shows a threshold choice.** ZAP saw the new cookie flags, but at LOW risk they do not block. That is deliberate: a passive scan's low alerts are mostly header hygiene. They stay on the dashboard instead of failing builds.

## 6. Metrics dashboard

`fortress/dashboard.py` renders a single self-contained HTML page in the consolidate job (artifact `metrics-dashboard`). The metrics were chosen to answer the CISO's questions, not to show volume:

| Question | Metric |
|---|---|
| Does shift-left work? | Seeded weaknesses caught before merge, against the 80% target |
| Is feedback fast enough for 30+ deploys a day? | Push → pre-build verdict (70 s), plus a job timeline |
| Is anything new blocking right now? | New findings above policy thresholds |
| Where does the volume come from? | Secrets in test code (62 of 69), container findings duplicating SCA (67 of 98), IaC failures in owned files (0 of 54) |
| How much is actionable? | Dependency findings with a fix available (120 of 168) |

Severity uses a single-hue ordinal ramp, validated for contrast and monotonic lightness in light and dark mode. Every chart has a table view, and all scanner-derived text is HTML-escaped (covered by tests).

## 7. Known gaps

- **JWT `alg: none` (seed 05):** add a custom SAST rule.
- **Authorization flaws (seed 11):** need authenticated DAST or a review checklist.
- **DAST depth:** the passive baseline does not exercise the Angular SPA's API surface. An authenticated ZAP API scan against the OpenAPI/REST routes is the next step.
- **Image digest in Kubernetes:** solvable with a local registry inside kind, and documented as a skip until then.
- **Frontend lockfile:** still resolved in CI (npm crashes locally while generating it).
