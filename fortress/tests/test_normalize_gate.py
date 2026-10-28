import json
from pathlib import Path

from fortress import gate, normalize

FIXTURES = Path(__file__).parent / "fixtures"
POLICY = {
    "secrets": {"fail_on": "LOW"},
    "sast": {"fail_on": "HIGH"},
    "sca": {"fail_on": "CRITICAL", "require_fix": True},
    "iac": {"fail_on": "LOW"},
    "container": {"fail_on": "CRITICAL", "require_fix": True},
    "dast": {"fail_on": "HIGH"},
}


def load(name):
    return json.loads((FIXTURES / name).read_text())


def all_findings():
    findings = (normalize.from_semgrep(load("semgrep.json"), FIXTURES / "src")
                + normalize.from_gitleaks(load("gitleaks.json"))
                + normalize.from_trivy(load("trivy-fs.json"))
                + normalize.from_checkov(load("checkov.json"))
                + normalize.from_zap(load("zap.json")))
    return normalize.to_json(normalize.dedupe(findings))


def baseline_of(findings, **extra):
    return {f["fingerprint"]: f["category"] for f in findings} | extra


def test_secret_values_never_reach_consolidated_output():
    dumped = json.dumps(all_findings())
    assert "AKIAFAKEFAKEFAKEFAKE" not in dumped
    assert "SELECT * FROM Users" not in dumped  # no code snippets either
    assert "SECRETSESSION123" not in dumped  # no ZAP request/response evidence


def test_semgrep_fingerprint_survives_line_shift(tmp_path):
    src = tmp_path / "routes"
    src.mkdir()
    (src / "login.ts").write_text((FIXTURES / "src/routes/login.ts").read_text())
    before = normalize.from_semgrep(load("semgrep.json"), tmp_path)[0].fingerprint

    (src / "login.ts").write_text("// new header comment\n" + (src / "login.ts").read_text())
    shifted = load("semgrep.json")
    shifted["results"][0]["start"]["line"] += 1
    after = normalize.from_semgrep(shifted, tmp_path)[0].fingerprint
    assert before == after


def test_trivy_duplicate_across_lockfiles_is_merged():
    sca = [f for f in all_findings() if f["category"] == "sca"]
    assert len(sca) == 2


def test_checkov_and_zap_are_normalised():
    by_cat = {}
    for f in all_findings():
        by_cat.setdefault(f["category"], []).append(f)
    assert {f["rule_id"] for f in by_cat["iac"]} == {"CKV_AWS_260", "CKV_PF_K8S_2"}
    assert all(f["severity"] == "MEDIUM" for f in by_cat["iac"])  # OSS Checkov has no severity
    assert {(f["rule_id"], f["severity"], tuple(f["cwe"])) for f in by_cat["dast"]} == {
        ("10038-1", "MEDIUM", ("CWE-693",)), ("10049", "INFO", ())}


def test_gate_blocks_only_new_findings_above_threshold():
    findings = all_findings()
    others = [f for f in findings if f["category"] != "secrets"]
    result = gate.evaluate(findings, baseline_of(others, old_secret="secrets"), POLICY)
    assert [f["category"] for f in result["blocking"]] == ["secrets"]
    assert result["resolved"] == 1


def test_gate_ignores_critical_cve_without_fix():
    findings = [f for f in all_findings() if f["category"] == "sca"]
    result = gate.evaluate(findings, {"old": "sca"}, POLICY, {"sca"})
    assert [f["cve"] for f in result["blocking"]] == ["CVE-2099-0001"]


def test_new_stage_bootstraps_without_blocking():
    findings = all_findings()
    armed = [f for f in findings if f["category"] not in ("iac", "dast")]
    result = gate.evaluate(findings, baseline_of(armed), POLICY)
    assert result["bootstrap"] == {"iac", "dast", "container"}
    assert result["blocking"] == []
    assert {f["category"] for f in result["new"]} == {"iac", "dast"}


def test_partial_gate_only_counts_its_own_stages():
    findings = all_findings()
    result = gate.evaluate(findings, baseline_of(findings, gone="sast"), POLICY, {"dast"})
    assert {f["category"] for f in result["findings"]} == {"dast"}
    assert result["resolved"] == 0  # the resolved SAST entry is not this job's business


def test_legacy_baseline_without_category_still_loads(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps({"fingerprints": {"abc": {"tool": "gitleaks", "rule_id": "jwt", "file": "x"}}}))
    assert gate.load_baseline(path) == {"abc": "secrets"}


def test_bootstrap_mode_never_blocks():
    result = gate.evaluate(all_findings(), None, POLICY)
    assert result["blocking"] == []
    assert len(result["new"]) == len(all_findings())
