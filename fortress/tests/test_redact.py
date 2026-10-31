"""Canary tests: plant fake secrets, code and identifiers everywhere a finding can
carry them, and prove none of them reaches an outbound payload."""
import json
from pathlib import Path

import pytest

from fortress.redact import Pseudonymiser, RedactionError, Redactor, scan_payload

from .test_normalize_gate import all_findings

_FIXTURE = json.loads((Path(__file__).parent / "fixtures/canaries.json").read_text())
# Fake values with the exact shape of real ones, kept in the gitleaks-allowlisted fixtures dir.
CANARIES = _FIXTURE["canaries"]
IDENTIFIERS = _FIXTURE["identifiers"]


def poisoned_findings():
    """Real-looking findings with canaries in every field, including ones outside the allowlist."""
    base = all_findings()
    poisoned = []
    for i, (name, canary) in enumerate({**CANARIES, **IDENTIFIERS}.items()):
        f = dict(base[i % len(base)])
        f.update(title=f"{f['title']} {canary}", snippet=canary, evidence=canary, secret=canary,
                 file=f"services/{IDENTIFIERS['host']}/handler.ts")
        poisoned.append(f)
    poisoned.append({**base[0], "category": "secrets", "title": CANARIES["aws"]})
    return poisoned


@pytest.mark.parametrize("name", CANARIES)
def test_guard_blocks_each_canary_on_its_own(name):
    with pytest.raises(RedactionError):
        Redactor().seal("Triage these findings.", {"note": CANARIES[name]})


@pytest.mark.parametrize("name", IDENTIFIERS)
def test_guard_blocks_unpseudonymised_identifiers(name):
    assert scan_payload(f"see {IDENTIFIERS[name]} for details")


def test_secrets_category_is_never_prepared():
    findings = poisoned_findings()
    redactor = Redactor()
    prepared = redactor.prepare(findings)
    assert all(f["category"] != "secrets" for f in prepared)
    assert len(redactor.withheld) == sum(f["category"] == "secrets" for f in findings)


def test_identifiers_are_pseudonymised_and_canaries_cannot_pass(tmp_path):
    redactor = Redactor(audit_dir=tmp_path)
    prepared = redactor.prepare(poisoned_findings())
    dumped = json.dumps(prepared)
    for value in IDENTIFIERS.values():
        assert value not in dumped
    assert "snippet" not in dumped and "evidence" not in dumped  # outside the allowlist
    # Canaries embedded in titles survive minimisation, so the guard must stop the send.
    with pytest.raises(RedactionError):
        redactor.seal("Triage these findings.", prepared)
    assert list(tmp_path.iterdir()) == []  # nothing recorded as sent


def test_clean_findings_pass_and_are_audited_byte_for_byte(tmp_path):
    redactor = Redactor(audit_dir=tmp_path)
    prepared = redactor.prepare(all_findings())
    payload = redactor.seal("Triage these findings.", prepared)
    (audit,) = tmp_path.iterdir()
    assert audit.read_text() == payload


def test_paths_round_trip_through_tokens():
    ps = Pseudonymiser()
    token = ps.path("routes/login.ts")
    assert token == "PATH_1.ts"
    assert ps.restore(f"Fix the query in {token} first.") == "Fix the query in routes/login.ts first."
