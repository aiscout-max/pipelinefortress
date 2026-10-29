import json

from fortress import remediate


def test_pick_version_prefers_smallest_fix_on_the_same_major():
    assert remediate.pick_version(["8.18.0"], ["5.2.5", "6.2.4", "7.5.11", "8.21.0"]) == "8.21.0"
    assert remediate.pick_version(["0.1.0", "0.4.0"], ["4.2.2"]) == "4.2.2"  # no same-major fix: next major
    assert remediate.pick_version(["3.3.0"], ["4.0.0", "4.2.0"]) == "4.0.0"
    assert remediate.pick_version(["2.0.0"], ["1.9.9"]) is None  # never downgrade
    assert remediate.pick_version(["1.0.0"], []) is None


def test_apply_fix_bumps_direct_and_overrides_transitive(tmp_path, monkeypatch):
    monkeypatch.setattr(remediate, "run", lambda *a, **k: "")  # no npm in unit tests
    (tmp_path / "package.json").write_text(json.dumps(
        {"author": "Björn", "dependencies": {"crypto-js": "^3.3.0"}, "devDependencies": {"vite": "~8.3.0"}},
        ensure_ascii=False))

    assert "direct dependency" in remediate.apply_fix(tmp_path, "crypto-js", "4.2.0")
    assert "direct devDependency" in remediate.apply_fix(tmp_path, "vite", "8.3.3")
    assert "override" in remediate.apply_fix(tmp_path, "tar", "7.5.19")

    assert "Björn" in (tmp_path / "package.json").read_text()  # no ö noise in the diff
    pkg = json.loads((tmp_path / "package.json").read_text())
    assert pkg["dependencies"]["crypto-js"] == "^4.2.0"  # keeps the range style
    assert pkg["devDependencies"]["vite"] == "~8.3.3"
    assert pkg["overrides"] == {"tar": "7.5.19"}


def test_pr_body_states_human_approval_and_provenance():
    cluster = {"cluster_id": "C001", "severity": "CRITICAL", "stages": ["container", "sca"], "members": ["a", "b"],
               "ids": ["CVE-2023-46233"], "rule_ids": ["CVE-2023-46233"], "package": "crypto-js",
               "installed_versions": ["3.3.0"], "rationale": "Weak PBKDF2 defaults.",
               "fix": ["Upgrade crypto-js to 4.2.0.", "Re-hash stored secrets.", "Re-run SCA."]}
    body = remediate.pr_body(cluster, "4.2.0", "bumped the direct dependency")
    assert "A human must review and approve" in body
    assert "not from model text" in body
    assert "- Upgrade crypto-js to 4.2.0." in body


def test_target_version_fixes_every_cve_in_a_package_cluster():
    tar = {"installed_versions": ["6.2.1"],
           "fixes": {"CVE-A": ["7.5.3"], "CVE-B": ["7.5.19"], "CVE-C": ["7.5.10"], "GHSA-none": []}}
    assert remediate.target_version(tar) == "7.5.19"
    assert remediate.fixable_ids(tar) == ["CVE-A", "CVE-B", "CVE-C"]
    minimatch = {"installed_versions": ["3.0.5"],
                 "fixes": {"CVE-1": ["10.2.3", "3.1.4", "4.2.5"], "CVE-2": ["10.2.1", "3.1.3", "4.2.4"]}}
    assert remediate.target_version(minimatch) == "3.1.4"  # stays on the installed major line
