"""Convert raw scanner reports into one consolidated findings list.

Every scanner speaks a different JSON dialect. This module maps them onto a
single schema so that the gate, the metrics dashboard and the LLM triage all
read the same thing.

Data minimisation happens here, at ingestion: code snippets, matched secret
values and raw request/response bodies are never copied into a Finding. The
consolidated file is therefore safe to upload as a public CI artifact and is
the only input the triage tool is allowed to read.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import SEVERITIES


@dataclass
class Finding:
    tool: str
    category: str  # sast | secrets | sca | container | iac | dast
    rule_id: str
    title: str
    severity: str
    file: str | None = None
    line: int | None = None
    cwe: list[str] = field(default_factory=list)
    cve: str | None = None
    package: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    fingerprint: str = ""

    @property
    def id(self) -> str:
        return self.fingerprint[:12]


def _digest(*parts: object) -> str:
    return hashlib.sha256("\x1f".join(str(p) for p in parts).encode()).hexdigest()


def _normalise_cwe(raw: object) -> list[str]:
    items = raw if isinstance(raw, list) else [raw] if raw else []
    out = []
    for item in items:
        match = re.search(r"CWE-\d+", str(item))
        if match and match.group(0) not in out:
            out.append(match.group(0))
    return out


def _source_line(source_root: Path, path: str, line: int) -> str:
    """Whitespace-normalised source line, used only to build a stable fingerprint."""
    try:
        lines = (source_root / path).read_text(errors="replace").splitlines()
        return " ".join(lines[line - 1].split())
    except (OSError, IndexError):
        return f"line:{line}"


# --- Semgrep (JSON) ---------------------------------------------------------

_SEMGREP_SEVERITY = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}


def from_semgrep(report: dict, source_root: Path) -> list[Finding]:
    findings = []
    for r in report.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        raw_sev = str(extra.get("severity", "INFO")).upper()
        severity = _SEMGREP_SEVERITY.get(raw_sev, raw_sev if raw_sev in SEVERITIES else "LOW")
        line = r.get("start", {}).get("line")
        # Fingerprint on the *content* of the line, not its number, so the
        # baseline survives unrelated edits that shift code up or down.
        findings.append(Finding(
            tool="semgrep",
            category="sast",
            rule_id=r["check_id"],
            title=str(extra.get("message", r["check_id"])).strip().splitlines()[0][:200],
            severity=severity,
            file=r.get("path"),
            line=line,
            cwe=_normalise_cwe(meta.get("cwe")),
            fingerprint=_digest("semgrep", r["check_id"], r.get("path"),
                                _source_line(source_root, r.get("path", ""), line or 0)),
        ))
    return findings


# --- gitleaks (JSON) --------------------------------------------------------

def from_gitleaks(report: list) -> list[Finding]:
    # Secret and Match fields are deliberately ignored. The fingerprint uses the
    # n-th occurrence of a rule in a file instead of hashing the secret, so not
    # even a hash of a credential is ever written to disk.
    occurrence: dict[tuple[str, str], int] = defaultdict(int)
    findings = []
    for r in sorted(report, key=lambda x: (x.get("File", ""), x.get("StartLine", 0))):
        key = (r.get("RuleID", ""), r.get("File", ""))
        occurrence[key] += 1
        findings.append(Finding(
            tool="gitleaks",
            category="secrets",
            rule_id=r.get("RuleID", "unknown"),
            title=r.get("Description", "Hard-coded secret"),
            severity="HIGH",
            file=r.get("File"),
            line=r.get("StartLine"),
            cwe=["CWE-798"],
            fingerprint=_digest("gitleaks", *key, occurrence[key]),
        ))
    return findings


# --- Trivy (JSON, fs or image) ----------------------------------------------

def from_trivy(report: dict, category: str = "sca") -> list[Finding]:
    findings = []
    for result in report.get("Results", []):
        # Target is a lockfile path for fs scans and a layer path for image
        # scans; Type (npm, debian, ...) is stable across both.
        target = result.get("Target", "")
        pkg_type = result.get("Type", "")
        for v in result.get("Vulnerabilities") or []:
            sev = str(v.get("Severity", "UNKNOWN")).upper()
            findings.append(Finding(
                tool="trivy",
                category=category,
                rule_id=v["VulnerabilityID"],
                title=(v.get("Title") or v["VulnerabilityID"])[:200],
                severity=sev if sev in SEVERITIES else "INFO",
                file=target,
                cwe=_normalise_cwe(v.get("CweIDs")),
                cve=v["VulnerabilityID"] if v["VulnerabilityID"].startswith("CVE-") else None,
                package=v.get("PkgName"),
                installed_version=v.get("InstalledVersion"),
                fixed_version=v.get("FixedVersion") or None,
                fingerprint=_digest("trivy", category, pkg_type, v["VulnerabilityID"],
                                    v.get("PkgName"), v.get("InstalledVersion")),
            ))
    return findings


# --- Checkov (JSON, one report per framework) -------------------------------

def from_checkov(report: dict | list) -> list[Finding]:
    reports = report if isinstance(report, list) else [report]
    findings = []
    for rep in reports:
        for c in rep.get("results", {}).get("failed_checks", []):
            sev = str(c.get("severity") or "MEDIUM").upper()  # OSS Checkov reports no severity
            path = c["file_path"].lstrip("/")
            findings.append(Finding(
                tool="checkov",
                category="iac",
                rule_id=c["check_id"],
                title=c["check_name"][:200],
                severity=sev if sev in SEVERITIES else "MEDIUM",
                file=path,
                line=(c.get("file_line_range") or [None])[0],
                # Resource names (e.g. aws_security_group.lb) are stable across
                # edits; line ranges are not.
                fingerprint=_digest("checkov", c["check_id"], path, c.get("resource")),
            ))
    return findings


# --- OWASP ZAP baseline (JSON) ----------------------------------------------

_ZAP_RISK = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}


def from_zap(report: dict) -> list[Finding]:
    # Instances carry request/response evidence (cookies, tokens, bodies).
    # Only the alert type is kept: one finding per alert per site.
    findings = []
    for site in report.get("site", []):
        for a in site.get("alerts", []):
            ref = a.get("alertRef") or a["pluginid"]
            cwe = str(a.get("cweid", ""))
            findings.append(Finding(
                tool="zap",
                category="dast",
                rule_id=ref,
                title=a.get("alert") or a.get("name", ref),
                severity=_ZAP_RISK.get(str(a.get("riskcode")), "INFO"),
                cwe=[f"CWE-{cwe}"] if cwe.isdigit() and int(cwe) > 0 else [],
                fingerprint=_digest("zap", ref),
            ))
    return findings


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Drop exact duplicates (same fingerprint), e.g. one CVE listed by two lockfiles."""
    seen: dict[str, Finding] = {}
    for f in findings:
        seen.setdefault(f.fingerprint, f)
    return list(seen.values())


def to_json(findings: list[Finding]) -> list[dict]:
    return [{"id": f.id, **asdict(f)} for f in findings]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--semgrep", type=Path)
    p.add_argument("--gitleaks", type=Path)
    p.add_argument("--trivy-fs", type=Path)
    p.add_argument("--trivy-image", type=Path)
    p.add_argument("--checkov", type=Path)
    p.add_argument("--zap", type=Path)
    p.add_argument("--source-root", type=Path, default=Path("."))
    p.add_argument("-o", "--output", type=Path, required=True)
    args = p.parse_args(argv)

    findings: list[Finding] = []
    if args.semgrep:
        findings += from_semgrep(json.loads(args.semgrep.read_text()), args.source_root)
    if args.gitleaks:
        findings += from_gitleaks(json.loads(args.gitleaks.read_text() or "[]"))
    if args.trivy_fs:
        findings += from_trivy(json.loads(args.trivy_fs.read_text()), "sca")
    if args.trivy_image:
        findings += from_trivy(json.loads(args.trivy_image.read_text()), "container")
    if args.checkov:
        findings += from_checkov(json.loads(args.checkov.read_text()))
    if args.zap:
        findings += from_zap(json.loads(args.zap.read_text()))

    findings = dedupe(findings)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(to_json(findings), indent=2))
    print(f"wrote {len(findings)} findings to {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
