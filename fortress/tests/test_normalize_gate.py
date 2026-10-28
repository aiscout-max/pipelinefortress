import json
from pathlib import Path

from fortress import gate, normalize

FIXTURES = Path(__file__).parent / "fixtures"
POLICY = {
    "secrets": {"fail_on": "LOW"},
    "sast": {"fail_on": "HIGH"},
    "sca": {"fail_on": "CRITICAL", "require_fix": True},
}


def load(name):
    return json.loads((FIXTURES / name).read_text())


def all_findings():
    findings = (normalize.from_semgrep(load("semgrep.json"), FIXTURES / "src")
                + normalize.from_gitleaks(load("gitleaks.json"))
                + normalize.from_trivy(load("trivy-fs.json")))
    return normalize.to_json(normalize.dedupe(findings))


def test_secret_values_never_reach_consolidated_output():
    dumped = json.dumps(all_findings())
    assert "AKIAFAKEFAKEFAKEFAKE" not in dumped
    assert "SELECT * FROM Users" not in dumped  # no code snippets either


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


def test_gate_blocks_only_new_findings_above_threshold():
    findings = all_findings()
    baseline = {f["fingerprint"] for f in findings if f["category"] != "secrets"}
    result = gate.evaluate(findings, baseline, POLICY)
    assert [f["category"] for f in result["blocking"]] == ["secrets"]


def test_gate_ignores_critical_cve_without_fix():
    findings = [f for f in all_findings() if f["category"] == "sca"]
    result = gate.evaluate(findings, set(), POLICY)
    assert [f["cve"] for f in result["blocking"]] == ["CVE-2099-0001"]


def test_bootstrap_mode_never_blocks():
    result = gate.evaluate(all_findings(), None, POLICY)
    assert result["blocking"] == []
    assert len(result["new"]) == len(all_findings())
