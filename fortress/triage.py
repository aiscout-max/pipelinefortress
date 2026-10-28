"""GenAI triage of consolidated findings: cluster, prioritise, suggest fixes.

Division of labour:
- Code does everything that must be exact: clustering duplicates, choosing
  what is eligible, redaction, and checking every identifier the model writes.
- The model (Gemini, via REST) does what code cannot: weigh exploitability in
  context, explain the risk, and draft a 3-5 line fix.
- A suggestion that fails validation is dropped and the cluster is marked for
  human triage. The tool never fills a gap with a guess.

usage: python3 -m fortress.triage --findings reports/findings.json -o reports/triage
       (needs GEMINI_API_KEY; --dry-run builds and audits the payloads without sending)
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path

from . import severity_rank
from .redact import NEVER_SEND_CATEGORIES, RedactionError, Redactor

DEFAULT_MODEL = "gemini-flash-latest"
RETRY_DELAYS = [10, 30, 90]  # seconds
REQUEST_TIMEOUT = 300  # seconds; a loaded free tier can take minutes per batch
BATCH_SIZE = 10
MAX_CLUSTERS = 30
_ID = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|GHSA(?:-[a-z0-9]{4}){3})\b")
# A trailing full stop ends the sentence, not the version ("upgrade to 4.17.21.").
_VERSION = re.compile(r"(?<![\w.])v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.]*[0-9A-Za-z])?)(?!\w|\.\d)")

SECRET_ADVICE = [
    "Treat the credential as compromised: revoke and rotate it at the issuer.",
    "Remove it from the code and purge it from git history.",
    "Load the replacement from a secret store or CI secret, never from source.",
]

PROMPT = """You are a senior application-security engineer triaging scanner results for an
e-commerce web application (Node.js/TypeScript, deployed as a container on Kubernetes).

Each cluster groups duplicate findings. File paths are pseudonymised as PATH_n tokens:
refer to them by token, never guess real names. You have no source code.

For EVERY cluster, return:
- priority: 1 (fix first) to 10 (can wait), judged on exploitability and impact.
- rationale: at most two sentences.
- fix: 3 to 5 short lines a developer can act on.
- likely_false_positive: true only if the finding is probably not a real risk
  (for example test-only code or a non-security use); explain in fp_reason.

Hard rules:
- Mention only vulnerability IDs (CVE/GHSA) that appear in that cluster's data.
- Recommend only versions listed in that cluster's fixed_versions.
- If you are not sure, say so in the rationale instead of inventing detail."""

RESPONSE_SCHEMA = {
    "type": "OBJECT",
    "properties": {"results": {"type": "ARRAY", "items": {
        "type": "OBJECT",
        "properties": {
            "cluster_id": {"type": "STRING"},
            "priority": {"type": "INTEGER"},
            "rationale": {"type": "STRING"},
            "fix": {"type": "ARRAY", "items": {"type": "STRING"}},
            "likely_false_positive": {"type": "BOOLEAN"},
            "fp_reason": {"type": "STRING"},
        },
        "required": ["cluster_id", "priority", "rationale", "fix", "likely_false_positive"],
    }}},
    "required": ["results"],
}


# ------------------------------------------------------------------ clustering

def cluster_key(f: dict) -> tuple:
    if f["category"] in ("sca", "container") and f.get("package"):
        return ("dep", f["rule_id"], f["package"])  # same CVE in lockfile and image
    if f["category"] == "sast" and f.get("file"):
        return ("code", f["file"], f.get("line"))  # several rules flagging one line
    if f["category"] == "iac":
        return ("iac", f["rule_id"], Path(f.get("file") or "").name, f.get("line"))  # duplicated TF trees
    return (f["category"], f["rule_id"], f.get("file"), f.get("line"))


def build_clusters(findings: list[dict]) -> list[dict]:
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for f in findings:
        groups[cluster_key(f)].append(f)
    clusters = []
    for members in groups.values():
        top = max(members, key=lambda f: severity_rank(f["severity"]))
        clusters.append({
            "category": top["category"],
            "severity": top["severity"],
            "title": top["title"],
            "rule_ids": sorted({f["rule_id"] for f in members}),
            "stages": sorted({f["category"] for f in members}),
            "ids": sorted({i for f in members for i in [f.get("cve") or "", f["rule_id"]] if _ID.fullmatch(i)}),
            "cwe": sorted({c for f in members for c in f.get("cwe") or []}),
            "package": top.get("package"),
            "installed_versions": sorted({f["installed_version"] for f in members if f.get("installed_version")}),
            "fixed_versions": sorted({v.strip() for f in members for v in (f.get("fixed_version") or "").split(",") if v.strip()}),
            "files": sorted({f["file"] for f in members if f.get("file")}),
            "line": top.get("line"),
            "members": [f["fingerprint"] for f in members],
        })
    # Deterministic pre-ranking decides which clusters the model sees at all.
    clusters.sort(key=lambda c: (-severity_rank(c["severity"]), not c["fixed_versions"],
                                 -len(c["members"]), c["title"]))
    for n, c in enumerate(clusters, 1):
        c["cluster_id"] = f"C{n:03d}"
    return clusters


# ------------------------------------------------------------------- model I/O

def gemini(payload_text: str, model: str, api_key: str) -> dict:
    prompt, _, data = payload_text.partition("\n\nDATA:\n")
    body = {
        "systemInstruction": {"parts": [{"text": prompt}]},
        "contents": [{"role": "user", "parts": [{"text": "DATA:\n" + data}]}],
        "generationConfig": {"temperature": 0, "responseMimeType": "application/json",
                             "responseSchema": RESPONSE_SCHEMA},
    }
    req = urllib.request.Request(
        f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "x-goog-api-key": api_key},
    )
    # Under load the free tier answers 429/503 or simply stalls; back off and
    # retry rather than give up on the batch.
    for attempt, delay in enumerate(RETRY_DELAYS + [None]):
        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                answer = json.load(resp)
            return json.loads(answer["candidates"][0]["content"]["parts"][0]["text"])
        except urllib.error.HTTPError as err:
            if err.code not in (429, 500, 503) or delay is None:
                raise
            reason = f"HTTP {err.code}"
        except (TimeoutError, ConnectionError) as err:
            if delay is None:
                raise
            reason = type(err).__name__
        print(f"model call failed ({reason}); retry {attempt + 1} in {delay}s", file=sys.stderr)
        time.sleep(delay)
    raise AssertionError("unreachable")


def outbound_view(cluster: dict, redactor: Redactor) -> dict:
    """What the model may see about a cluster: pseudonymised paths, no fingerprints."""
    view = {k: cluster[k] for k in ("cluster_id", "category", "severity", "title", "rule_ids", "stages",
                                    "ids", "cwe", "package", "installed_versions", "fixed_versions")
            if cluster.get(k) not in (None, [], "")}
    view["files"] = [redactor.ps.path(p) for p in cluster["files"][:5]]
    view["occurrences"] = len(cluster["members"])
    view["title"] = redactor.ps.text(view["title"])
    return view


# ------------------------------------------------------------------ validation

def validate(result: dict, cluster: dict) -> list[str]:
    """Reasons to reject the model's suggestion for this cluster (empty = accept)."""
    problems = []
    fix = result.get("fix") or []
    if not 3 <= len(fix) <= 5:
        problems.append(f"fix has {len(fix)} lines, expected 3-5")
    if not isinstance(result.get("priority"), int) or not 1 <= result["priority"] <= 10:
        problems.append("priority outside 1-10")
    text = " ".join([result.get("rationale", ""), result.get("fp_reason", ""), *fix])
    invented = set(_ID.findall(text)) - set(cluster["ids"])
    if invented:
        problems.append("hallucinated identifier: " + ", ".join(sorted(invented)))
    if cluster["category"] in ("sca", "container"):
        allowed = set(cluster["fixed_versions"]) | set(cluster["installed_versions"])
        unknown = set(_VERSION.findall(" ".join(fix))) - allowed
        if unknown:
            problems.append("version not reported by the scanner: " + ", ".join(sorted(unknown)))
    return problems


# ---------------------------------------------------------------------- triage

def triage(findings: list[dict], audit_dir: Path, model: str, api_key: str | None, dry_run: bool) -> dict:
    redactor = Redactor(audit_dir=audit_dir)
    clusters = build_clusters(findings)
    stats = {"findings": len(findings), "clusters": len(clusters), "sent_to_model": 0, "accepted": 0,
             "rejected": 0, "hallucinated_ids": 0, "withheld_secrets": 0, "blocked_payloads": 0}
    for c in clusters:
        if c["category"] in NEVER_SEND_CATEGORIES:
            c.update(status="withheld: secret", priority=1, fix=SECRET_ADVICE,
                     rationale="Secret values never leave the runner, so this is not sent to the model.")
            stats["withheld_secrets"] += 1
        else:
            c.update(status="not triaged (below the top clusters)")

    # Clusters never mix categories (see cluster_key), so a secrets cluster holds only secrets.
    to_send = [c for c in clusters if c["category"] not in NEVER_SEND_CATEGORIES][:MAX_CLUSTERS]
    for start in range(0, len(to_send), BATCH_SIZE):
        batch = to_send[start:start + BATCH_SIZE]
        try:
            payload = redactor.seal(PROMPT, [outbound_view(c, redactor) for c in batch])
        except RedactionError as err:
            stats["blocked_payloads"] += 1
            for c in batch:
                c.update(status="needs human triage", rationale=f"Payload blocked by the redaction guard ({err}).")
            continue
        stats["sent_to_model"] += len(batch)
        if dry_run:
            for c in batch:
                c["status"] = "dry run: payload audited, not sent"
            continue
        try:
            answer = gemini(payload, model, api_key or "")
        except (OSError, KeyError, ValueError) as err:  # OSError covers URLError and timeouts
            reason = f"HTTP {err.code}" if isinstance(err, urllib.error.HTTPError) else type(err).__name__
            for c in batch:
                c.update(status="needs human triage", rationale=f"Model call failed ({reason}).")
            continue
        by_id = {r.get("cluster_id"): r for r in answer.get("results", [])}
        for c in batch:
            result = by_id.get(c["cluster_id"])
            problems = validate(result, c) if result else ["no answer for this cluster"]
            if problems:
                stats["rejected"] += 1
                stats["hallucinated_ids"] += sum(p.startswith("hallucinated") for p in problems)
                c.update(status="needs human triage", rejected_because=problems)
                continue
            stats["accepted"] += 1
            c.update(
                status="triaged",
                priority=result["priority"],
                rationale=redactor.ps.restore(result["rationale"]),
                fix=[redactor.ps.restore(line) for line in result["fix"]],
                likely_false_positive=result["likely_false_positive"],
                fp_reason=redactor.ps.restore(result.get("fp_reason", "")),
            )

    order = {"withheld: secret": 0, "triaged": 1}
    clusters.sort(key=lambda c: (order.get(c["status"], 2), c.get("priority", 11),
                                 -severity_rank(c["severity"]), c["cluster_id"]))
    return {"model": model, "stats": stats, "clusters": clusters}


def render_markdown(result: dict, top: int = 15) -> str:
    s = result["stats"]
    out = ["# GenAI triage", "",
           f"Model `{result['model']}`. {s['findings']} findings → {s['clusters']} clusters. "
           f"{s['sent_to_model']} clusters sent after redaction; {s['accepted']} suggestions accepted, "
           f"{s['rejected']} rejected by validation ({s['hallucinated_ids']} for invented identifiers). "
           f"{s['withheld_secrets']} secret clusters were never sent.", "",
           "| # | Cluster | Severity | Stages | Occurrences | Status |", "|---:|---|---|---|---:|---|"]
    for n, c in enumerate(result["clusters"][:top], 1):
        out.append(f"| {n} | {c['cluster_id']} {c['title'][:70]} | {c['severity']} | {', '.join(c['stages'])} | "
                   f"{len(c['members'])} | {c['status']} |")
    for c in result["clusters"][:top]:
        if c.get("fix"):
            out += ["", f"### {c['cluster_id']}: {c['title'][:90]}", ""]
            if c.get("rationale"):
                out += [c["rationale"], ""]
            out += [f"- {line}" for line in c["fix"]]
            if c.get("likely_false_positive"):
                out += ["", f"_Likely false positive: {c.get('fp_reason', '')}_"]
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--findings", type=Path, required=True)
    p.add_argument("-o", "--output", type=Path, required=True, help="output directory")
    p.add_argument("--model", default=os.environ.get("GEMINI_MODEL", DEFAULT_MODEL))
    p.add_argument("--dry-run", action="store_true", help="build and audit payloads without calling the model")
    args = p.parse_args(argv)

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key and not args.dry_run:
        print("GEMINI_API_KEY is not set (use --dry-run to audit payloads only)", file=sys.stderr)
        return 2
    result = triage(json.loads(args.findings.read_text()), args.output / "llm-audit",
                    args.model, api_key, args.dry_run)
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "triage.json").write_text(json.dumps(result, indent=2) + "\n")
    (args.output / "triage.md").write_text(render_markdown(result))
    print(json.dumps(result["stats"]), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
