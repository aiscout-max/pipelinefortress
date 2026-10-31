"""GenAI triage of consolidated findings: cluster, prioritise, suggest fixes.

Division of labour:
- Code does everything that must be exact: clustering duplicates, choosing
  what is eligible, redaction, and checking every identifier the model writes.
- The model (via REST) does what code cannot: weigh exploitability in
  context, explain the risk, and draft a 3-5 line fix. Providers are tried in
  order (OpenRouter, then Gemini); a batch falls back to the next one when a
  provider is down, rate-limited or answers with something unparseable.
- A suggestion that fails validation is dropped and the cluster is marked for
  human triage. The tool never fills a gap with a guess.

usage: python3 -m fortress.triage --findings reports/findings.json -o reports/triage
       (needs OPENROUTER_API_KEY and/or GEMINI_API_KEY; --dry-run builds and audits
       the payloads without sending)
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
from collections import defaultdict, deque
from pathlib import Path

from . import severity_rank
from .redact import NEVER_SEND_CATEGORIES, RedactionError, Redactor
from .remediate import target_version

# (provider, API key variable, model variable, default model), in fallback order.
PROVIDERS = [
    ("openrouter", "OPENROUTER_API_KEY", "OPENROUTER_MODEL", "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free"),
    ("gemini", "GEMINI_API_KEY", "GEMINI_MODEL", "gemini-flash-latest"),
]
RETRY_DELAYS = [10, 30, 90]  # seconds; a provider with a fallback behind it gets only the first
RETRY_CODES = (429, 500, 502, 503, 504)
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

# Versioned in the prompt library; see fortress/prompts/README.md.
PROMPT_FILE = Path(__file__).parent / "prompts" / "triage-system-v1.md"
PROMPT = PROMPT_FILE.read_text().strip()

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
        # One upgrade fixes every CVE of a package, in the lockfile and the image alike.
        return ("dep", f["package"])
    if f["category"] == "sast" and f.get("file"):
        return ("code", f["file"], f.get("line"))  # several rules flagging one line
    if f["category"] == "iac":
        return ("iac", f["rule_id"], Path(f.get("file") or "").name, f.get("line"))  # duplicated TF trees
    return (f["category"], f["rule_id"], f.get("file"), f.get("line"))


def split_versions(value: str | None) -> list[str]:
    """'8.3.3, 8.2.4' -> ['8.2.4', '8.3.3']; '>=4.2.2' -> ['4.2.2'] (a fix floor is a version)."""
    return sorted({re.sub(r"^[>=~^\s]+", "", v).strip() for v in (value or "").split(",") if v.strip()})


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
            "fixed_versions": sorted({v for f in members for v in split_versions(f.get("fixed_version"))}),
            # Per vulnerability, the versions that fix it; the upgrade target must satisfy all of them.
            "fixes": {f["cve"] or f["rule_id"]: split_versions(f.get("fixed_version")) for f in members
                      if f["category"] in ("sca", "container")},
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


# Clusters per round when choosing what the model sees. Without this the top
# 30 by severity were all dependency clusters and the model never judged a
# single SAST, IaC or DAST finding, which is where false positives live.
SELECTION_WEIGHTS = {"dependencies": 2, "sast": 2, "iac": 1, "dast": 1}


def select_for_model(clusters: list[dict], limit: int = MAX_CLUSTERS) -> list[dict]:
    queues: dict[str, deque] = {lane: deque() for lane in SELECTION_WEIGHTS}
    for c in clusters:  # already in pre-rank order
        if c["category"] in NEVER_SEND_CATEGORIES:
            continue
        lane = "dependencies" if c["category"] in ("sca", "container") else c["category"]
        queues.setdefault(lane, deque()).append(c)
    picked: list[dict] = []
    while len(picked) < limit and any(queues.values()):
        for lane, queue in queues.items():
            for _ in range(SELECTION_WEIGHTS.get(lane, 1)):
                if queue and len(picked) < limit:
                    picked.append(queue.popleft())
    return picked


# ------------------------------------------------------------------- model I/O

def failure_reason(err: Exception) -> str:
    return f"HTTP {err.code}" if isinstance(err, urllib.error.HTTPError) else type(err).__name__


def post_json(req: urllib.request.Request, delays: list[int]) -> dict:
    # Under load free tiers answer 429/503 or simply stall; back off and
    # retry rather than give up on the batch.
    for attempt, delay in enumerate(delays + [None]):
        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as err:
            if err.code not in RETRY_CODES or delay is None:
                raise
            reason = f"HTTP {err.code}"
        except (TimeoutError, ConnectionError) as err:
            if delay is None:
                raise
            reason = type(err).__name__
        print(f"model call failed ({reason}); retry {attempt + 1} in {delay}s", file=sys.stderr)
        time.sleep(delay)
    raise AssertionError("unreachable")


def gemini(payload_text: str, model: str, api_key: str, delays: list[int]) -> dict:
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
    answer = post_json(req, delays)
    return json.loads(answer["candidates"][0]["content"]["parts"][0]["text"])


def json_schema(schema: dict) -> dict:
    """RESPONSE_SCHEMA (Gemini's OpenAPI dialect) as strict JSON Schema for OpenAI-style APIs."""
    out = {**schema, "type": schema["type"].lower()}
    if "properties" in schema:
        out["properties"] = {k: json_schema(v) for k, v in schema["properties"].items()}
        out["required"] = list(schema["properties"])  # strict mode wants every key
        out["additionalProperties"] = False
    if "items" in schema:
        out["items"] = json_schema(schema["items"])
    return out


def openrouter(payload_text: str, model: str, api_key: str, delays: list[int]) -> dict:
    prompt, _, data = payload_text.partition("\n\nDATA:\n")
    body = {
        "model": model,
        "temperature": 0,
        "reasoning": {"enabled": True},  # reasoning comes back in its own field, not in content
        "messages": [{"role": "system", "content": prompt}, {"role": "user", "content": "DATA:\n" + data}],
        "response_format": {"type": "json_schema", "json_schema": {
            "name": "triage", "strict": True, "schema": json_schema(RESPONSE_SCHEMA)}},
    }
    req = urllib.request.Request(
        "https://openrouter.ai/api/v1/chat/completions",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}",
                 "X-Title": "PipelineFortress"},
    )
    answer = post_json(req, delays)
    if "error" in answer:  # upstream failures can arrive inside an HTTP 200
        raise ValueError(f"OpenRouter error: {answer['error']}")
    return json.loads(answer["choices"][0]["message"]["content"])


def ask_model(payload_text: str, providers: list[tuple[str, str, str]]) -> tuple[str, dict]:
    """(model, answer) from the first provider that answers; the last one's error propagates."""
    for n, (name, model, api_key) in enumerate(providers):
        last = n == len(providers) - 1
        call = {"openrouter": openrouter, "gemini": gemini}[name]
        try:
            return model, call(payload_text, model, api_key, RETRY_DELAYS if last else RETRY_DELAYS[:1])
        except (OSError, KeyError, ValueError) as err:  # OSError covers URLError and timeouts
            if last:
                raise
            print(f"{model} failed ({failure_reason(err)}); falling back to {providers[n + 1][1]}",
                  file=sys.stderr)
    raise ValueError("no model provider configured")


def outbound_view(cluster: dict, redactor: Redactor) -> dict:
    """What the model may see about a cluster: pseudonymised paths, no fingerprints."""
    view = {k: cluster[k] for k in ("cluster_id", "category", "severity", "title", "rule_ids", "stages",
                                    "ids", "cwe", "package", "installed_versions", "fixed_versions")
            if cluster.get(k) not in (None, [], "")}
    view["files"] = [redactor.ps.path(p) for p in cluster["files"][:5]]
    if target_version(cluster):
        view["upgrade_to"] = target_version(cluster)  # fixes every fixable CVE in the cluster
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

def triage(findings: list[dict], audit_dir: Path, providers: list[tuple[str, str, str]], dry_run: bool) -> dict:
    redactor = Redactor(audit_dir=audit_dir)
    clusters = build_clusters(findings)
    stats = {"findings": len(findings), "clusters": len(clusters), "sent_to_model": 0, "accepted": 0,
             "rejected": 0, "hallucinated_ids": 0, "withheld_secrets": 0, "blocked_payloads": 0,
             "answered_by": {}}
    for c in clusters:
        if c["category"] in NEVER_SEND_CATEGORIES:
            c.update(status="withheld: secret", priority=1, fix=SECRET_ADVICE,
                     rationale="Secret values never leave the runner, so this is not sent to the model.")
            stats["withheld_secrets"] += 1
        else:
            c.update(status="not triaged (below the top clusters)")

    # Clusters never mix secrets with anything else (see cluster_key).
    to_send = select_for_model(clusters)
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
            model, answer = ask_model(payload, providers)
        except (OSError, KeyError, ValueError) as err:
            for c in batch:
                c.update(status="needs human triage", rationale=f"Model call failed ({failure_reason(err)}).")
            continue
        stats["answered_by"][model] = stats["answered_by"].get(model, 0) + len(batch)
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
                model=model,
                priority=result["priority"],
                rationale=redactor.ps.restore(result["rationale"]),
                fix=[redactor.ps.restore(line) for line in result["fix"]],
                likely_false_positive=result["likely_false_positive"],
                fp_reason=redactor.ps.restore(result.get("fp_reason", "")),
            )

    order = {"withheld: secret": 0, "triaged": 1}
    clusters.sort(key=lambda c: (order.get(c["status"], 2), c.get("priority", 11),
                                 -severity_rank(c["severity"]), c["cluster_id"]))
    return {"models": [model for _, model, _ in providers], "stats": stats, "clusters": clusters}


def render_markdown(result: dict, top: int = 15) -> str:
    s = result["stats"]
    answered = ", ".join(f"`{m}` {n}" for m, n in s["answered_by"].items()) or "none"
    out = ["# GenAI triage", "",
           f"Models, in fallback order: {' → '.join(f'`{m}`' for m in result['models']) or 'none'} "
           f"(clusters answered: {answered}). {s['findings']} findings → {s['clusters']} clusters. "
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
    p.add_argument("--dry-run", action="store_true", help="build and audit payloads without calling the model")
    args = p.parse_args(argv)

    # Every provider whose key is set, in fallback order; models via OPENROUTER_MODEL / GEMINI_MODEL.
    providers = [(name, os.environ.get(model_var) or default, os.environ[key_var])
                 for name, key_var, model_var, default in PROVIDERS if os.environ.get(key_var)]
    if not providers and not args.dry_run:
        print("Neither OPENROUTER_API_KEY nor GEMINI_API_KEY is set (use --dry-run to audit payloads only)",
              file=sys.stderr)
        return 2
    result = triage(json.loads(args.findings.read_text()), args.output / "llm-audit",
                    providers, args.dry_run)
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "triage.json").write_text(json.dumps(result, indent=2) + "\n")
    (args.output / "triage.md").write_text(render_markdown(result))
    print(json.dumps(result["stats"]), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
