# Prompt library

Prompts are versioned files, never inline strings, so every model call can be
traced to the exact instructions it ran with. The audit log in
`reports/triage/llm-audit/` starts each payload with the prompt text; run 1
was checked byte-for-byte against `triage-system-v1.md`.

| Prompt | Used by | Model | Output contract |
|---|---|---|---|
| [`triage-system-v1.md`](triage-system-v1.md) | `fortress/triage.py` (system instruction) | `nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free` via OpenRouter, falling back to `gemini-flash-latest`; temperature 0 | JSON matching `RESPONSE_SCHEMA` in `triage.py` |

## How the prompts are written

1. **State what the model does not have.** "You have no source code" and
   "paths are pseudonymised" stop the model from inventing file contents or
   real path names. The redaction layer guarantees both; the prompt makes the
   model aware of them.
2. **Constrain identifiers to the input.** "Mention only vulnerability IDs that
   appear in that cluster's data" and "recommend only versions listed in
   fixed_versions". The validator in `triage.py` enforces both independently.
   The prompt lowers the rejection rate; it is not the control.
3. **Prefer an admitted gap to a guess.** "If you are not sure, say so in the
   rationale."
4. **Ask for a decision, not prose.** priority 1 to 10, a two-sentence
   rationale, 3 to 5 fix lines, and a likely-false-positive flag with a reason.
   Every field is checked.
5. **Structured output enforced by the API**, not by asking nicely:
   `responseMimeType: application/json` plus a `responseSchema` on Gemini, and
   the same schema as a strict `response_format: json_schema` on OpenRouter.
   Both providers get the identical prompt and data, so a fallback does not
   change what the audit log says was sent.

## Changelog

- **v1:** initial triage prompt. Added `upgrade_to` (the one version that fixes
  every CVE in a package cluster) when clustering moved from per-CVE to
  per-package.

## Results with v1

From the first real run on the Phase 2 findings (20 of 30 clusters answered;
one batch was lost to HTTP 503s in both attempts), scored against
`metrics/triage-labels.json`:

- 0 invented CVE/GHSA identifiers and 0 invented versions in the 20 answers
- Recall on real issues 1.0: no real issue was dismissed as a false positive
- No false positive was flagged. Without code or reachability context, the
  model cannot tell a build-time dependency or an ORM call from an
  exploitable one. See the final report, "Privacy versus context".

## Writing a v2

Copy the file to `-v2.md`, change `PROMPT_FILE` in `triage.py`, re-run
`python3 -m fortress.triage --dry-run` to audit the payloads, then a real run,
then `metrics/score_triage.py`. Keep v1 for comparison.
