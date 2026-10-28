from fortress import triage

from .test_normalize_gate import all_findings


def findings_with_duplicates():
    findings = all_findings()
    lodash = next(f for f in findings if f.get("package") == "lodash")
    # The same CVE seen again by the image scan, and a second SAST rule on the same line.
    findings.append({**lodash, "category": "container", "fingerprint": "f" * 64})
    sql = next(f for f in findings if f["category"] == "sast")
    findings.append({**sql, "rule_id": "express-sequelize-injection", "fingerprint": "e" * 64})
    return findings


def cluster_for(clusters, **match):
    return next(c for c in clusters if all(c.get(k) == v for k, v in match.items()))


def test_duplicates_across_stages_and_rules_cluster_together():
    clusters = triage.build_clusters(findings_with_duplicates())
    lodash = cluster_for(clusters, package="lodash")
    assert lodash["stages"] == ["container", "sca"] and len(lodash["members"]) == 2
    sql = cluster_for(clusters, category="sast")
    assert len(sql["rule_ids"]) == 2
    assert [c["cluster_id"] for c in clusters] == [f"C{n:03d}" for n in range(1, len(clusters) + 1)]


def test_validation_rejects_invented_ids_and_versions():
    lodash = cluster_for(triage.build_clusters(all_findings()), package="lodash")
    good = {"cluster_id": lodash["cluster_id"], "priority": 2, "rationale": "Prototype pollution (CVE-2099-0001).",
            "fix": ["Upgrade lodash to 4.17.21.", "Regenerate the lockfile.", "Re-run the SCA stage."],
            "likely_false_positive": False}
    assert triage.validate(good, lodash) == []
    invented = {**good, "rationale": "Also see CVE-2021-23337."}
    assert any("hallucinated" in p for p in triage.validate(invented, lodash))
    wrong_version = {**good, "fix": ["Upgrade lodash to 4.18.0.", "Regenerate the lockfile.", "Re-test."]}
    assert any("version" in p for p in triage.validate(wrong_version, lodash))
    too_short = {**good, "fix": ["Upgrade."]}
    assert any("3-5" in p for p in triage.validate(too_short, lodash))


def test_triage_accepts_valid_rejects_invalid_and_never_sends_secrets(tmp_path, monkeypatch):
    sent = []

    def fake_gemini(payload, model, api_key):
        sent.append(payload)
        ids = [line.split('"')[3] for line in payload.splitlines() if '"cluster_id"' in line]
        results = [{"cluster_id": ids[0], "priority": 1, "rationale": "Real risk.",
                    "fix": ["Do one thing.", "Then another.", "Then verify."], "likely_false_positive": False},
                   {"cluster_id": ids[1], "priority": 2, "rationale": "Like CVE-1999-9999.",
                    "fix": ["a", "b", "c"], "likely_false_positive": False}]
        return {"results": results}  # every other cluster gets no answer

    monkeypatch.setattr(triage, "gemini", fake_gemini)
    result = triage.triage(findings_with_duplicates(), tmp_path / "audit", "test-model", "key", dry_run=False)

    stats = result["stats"]
    assert stats["accepted"] == 1 and stats["hallucinated_ids"] == 1
    assert stats["rejected"] == stats["sent_to_model"] - 1
    assert stats["withheld_secrets"] == 1
    secret = next(c for c in result["clusters"] if c["category"] == "secrets")
    assert secret["status"] == "withheld: secret" and secret["fix"] == triage.SECRET_ADVICE
    audited = "".join(p.read_text() for p in (tmp_path / "audit").iterdir())
    assert audited == "".join(sent)  # the audit log is exactly what left the runner
    assert "routes/login.ts" not in audited and "config/settings.ts" not in audited


def test_network_failure_marks_batch_for_humans_instead_of_crashing(tmp_path, monkeypatch):
    def stalled(*_args):
        raise TimeoutError("The read operation timed out")

    monkeypatch.setattr(triage, "gemini", stalled)
    result = triage.triage(all_findings(), tmp_path / "audit", "test-model", "key", dry_run=False)
    sent = [c for c in result["clusters"] if c["category"] != "secrets"]
    assert {c["status"] for c in sent} == {"needs human triage"}
    assert {c["rationale"] for c in sent} == {"Model call failed (TimeoutError)."}


def test_dry_run_audits_without_calling_the_model(tmp_path, monkeypatch):
    def boom(*_args):
        raise AssertionError("model must not be called in a dry run")

    monkeypatch.setattr(triage, "gemini", boom)
    result = triage.triage(all_findings(), tmp_path / "audit", "test-model", None, dry_run=True)
    assert result["stats"]["sent_to_model"] > 0
    assert list((tmp_path / "audit").iterdir())
