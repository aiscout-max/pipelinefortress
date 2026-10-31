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


OPENROUTER_ONLY = [("openrouter", "test-model", "key")]
BOTH = [("openrouter", "primary-model", "key"), ("gemini", "fallback-model", "key")]


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

    def fake_openrouter(payload, model, api_key, delays):
        sent.append(payload)
        ids = [line.split('"')[3] for line in payload.splitlines() if '"cluster_id"' in line]
        results = [{"cluster_id": ids[0], "priority": 1, "rationale": "Real risk.",
                    "fix": ["Do one thing.", "Then another.", "Then verify."], "likely_false_positive": False},
                   {"cluster_id": ids[1], "priority": 2, "rationale": "Like CVE-1999-9999.",
                    "fix": ["a", "b", "c"], "likely_false_positive": False}]
        return {"results": results}  # every other cluster gets no answer

    monkeypatch.setattr(triage, "openrouter", fake_openrouter)
    result = triage.triage(findings_with_duplicates(), tmp_path / "audit", OPENROUTER_ONLY, dry_run=False)

    stats = result["stats"]
    assert stats["accepted"] == 1 and stats["hallucinated_ids"] == 1
    assert stats["rejected"] == stats["sent_to_model"] - 1
    assert stats["withheld_secrets"] == 1
    assert stats["answered_by"] == {"test-model": stats["sent_to_model"]}
    secret = next(c for c in result["clusters"] if c["category"] == "secrets")
    assert secret["status"] == "withheld: secret" and secret["fix"] == triage.SECRET_ADVICE
    audited = "".join(p.read_text() for p in (tmp_path / "audit").iterdir())
    assert audited == "".join(sent)  # the audit log is exactly what left the runner
    assert "routes/login.ts" not in audited and "config/settings.ts" not in audited


def test_network_failure_marks_batch_for_humans_instead_of_crashing(tmp_path, monkeypatch):
    def stalled(*_args):
        raise TimeoutError("The read operation timed out")

    monkeypatch.setattr(triage, "openrouter", stalled)
    monkeypatch.setattr(triage, "gemini", stalled)
    result = triage.triage(all_findings(), tmp_path / "audit", BOTH, dry_run=False)
    sent = [c for c in result["clusters"] if c["category"] != "secrets"]
    assert {c["status"] for c in sent} == {"needs human triage"}
    assert {c["rationale"] for c in sent} == {"Model call failed (TimeoutError)."}


def test_unavailable_provider_falls_back_to_the_next(tmp_path, monkeypatch):
    calls = []

    def unavailable(payload, model, api_key, delays):
        calls.append((model, delays))
        raise TimeoutError("The read operation timed out")

    def answers(payload, model, api_key, delays):
        calls.append((model, delays))
        return {"results": []}

    monkeypatch.setattr(triage, "openrouter", unavailable)
    monkeypatch.setattr(triage, "gemini", answers)
    result = triage.triage(all_findings(), tmp_path / "audit", BOTH, dry_run=False)
    assert result["stats"]["answered_by"] == {"fallback-model": result["stats"]["sent_to_model"]}
    # The primary gets one quick retry before falling over; the last provider gets the full backoff.
    assert calls[:2] == [("primary-model", triage.RETRY_DELAYS[:1]), ("fallback-model", triage.RETRY_DELAYS)]
    assert result["models"] == ["primary-model", "fallback-model"]


def test_dry_run_audits_without_calling_the_model(tmp_path, monkeypatch):
    def boom(*_args):
        raise AssertionError("model must not be called in a dry run")

    monkeypatch.setattr(triage, "openrouter", boom)
    monkeypatch.setattr(triage, "gemini", boom)
    result = triage.triage(all_findings(), tmp_path / "audit", [], dry_run=True)
    assert result["stats"]["sent_to_model"] > 0
    assert list((tmp_path / "audit").iterdir())


def test_fix_floors_are_normalised():
    assert triage.split_versions(">=4.2.2") == ["4.2.2"]
    assert triage.split_versions("8.3.3, 8.2.4") == ["8.2.4", "8.3.3"]
    assert triage.split_versions(None) == []


def test_model_sees_every_stage_not_just_dependencies():
    deps = [{"category": "sca", "cluster_id": f"D{i}"} for i in range(40)]
    others = ([{"category": "sast", "cluster_id": f"S{i}"} for i in range(40)]
              + [{"category": "iac", "cluster_id": f"I{i}"} for i in range(40)]
              + [{"category": "dast", "cluster_id": "Z1"}]
              + [{"category": "secrets", "cluster_id": "X1"}])
    picked = triage.select_for_model(deps + others, limit=30)
    lanes = [c["category"] for c in picked]
    assert len(picked) == 30 and "secrets" not in lanes
    # Weights 2:2:1:1 per round; the dast lane runs dry after one, the last round is cut at 30.
    assert (lanes.count("sca"), lanes.count("sast"), lanes.count("iac"), lanes.count("dast")) == (12, 12, 5, 1)
    assert [c["cluster_id"] for c in picked if c["category"] == "sca"][:3] == ["D0", "D1", "D2"]  # rank order kept
