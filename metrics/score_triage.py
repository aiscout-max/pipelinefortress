"""Score the model's triage verdicts against hand-made ground truth.

Positive class = "real issue". The model predicts real when it does NOT set
likely_false_positive. Clusters whose suggestion was rejected by validation,
or that are labelled uncertain, are reported separately, not silently dropped.

usage: python3 metrics/score_triage.py reports/triage/triage.json [metrics/triage-labels.json]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def score(triage: dict, labels: dict) -> dict:
    by_id = {c["cluster_id"]: c for c in triage["clusters"]}
    rows, uncertain, not_judged = [], [], []
    for lab in labels["labels"]:
        c = by_id.get(lab["cluster"])
        if lab["label"] == "uncertain":
            uncertain.append(lab["cluster"])
            continue
        if not c or c["status"] != "triaged":
            not_judged.append({"cluster": lab["cluster"], "status": c["status"] if c else "missing",
                               "rejected_because": (c or {}).get("rejected_because", [])})
            continue
        predicted_real = not c.get("likely_false_positive")
        actual_real = lab["label"] == "real"
        outcome = {(True, True): "TP", (True, False): "FP", (False, True): "FN", (False, False): "TN"}[
            (predicted_real, actual_real)]
        rows.append({"cluster": lab["cluster"], "key": lab["key"], "label": lab["label"], "outcome": outcome,
                     "category": c["category"], "priority": c.get("priority"), "model_fp_reason": c.get("fp_reason", "")})

    n = {k: sum(r["outcome"] == k for r in rows) for k in ("TP", "FP", "FN", "TN")}
    ratio = lambda a, b: round(a / b, 3) if b else None  # noqa: E731
    real_prio = [r["priority"] for r in rows if r["label"] == "real"]
    fp_prio = [r["priority"] for r in rows if r["label"] == "fp"]
    return {
        "confusion": n,
        "precision_real": ratio(n["TP"], n["TP"] + n["FP"]),
        "recall_real": ratio(n["TP"], n["TP"] + n["FN"]),
        "noise_caught": ratio(n["TN"], n["TN"] + n["FP"]),  # share of true FPs the model flagged
        "accuracy": ratio(n["TP"] + n["TN"], len(rows)),
        "mean_priority_real": ratio(sum(real_prio), len(real_prio)),
        "mean_priority_fp": ratio(sum(fp_prio), len(fp_prio)),
        "judged": len(rows), "uncertain": uncertain, "not_judged": not_judged,
        "validation": triage["stats"],
        "rows": rows,
    }


def main() -> int:
    triage = json.loads(Path(sys.argv[1]).read_text())
    labels = json.loads(Path(sys.argv[2] if len(sys.argv) > 2 else "metrics/triage-labels.json").read_text())
    result = score(triage, labels)
    print(json.dumps({k: v for k, v in result.items() if k != "rows"}, indent=2))
    for r in result["rows"]:
        if r["outcome"] in ("FP", "FN"):
            print(f"{r['outcome']} {r['cluster']} {r['key']} (label {r['label']}): {r['model_fp_reason'][:120]}")
    out = Path("metrics/triage-eval.json")
    out.write_text(json.dumps(result, indent=2) + "\n")
    print(f"-> {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
