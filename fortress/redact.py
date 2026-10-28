"""Redaction layer: the only code path by which finding data may leave the runner.

Three independent defences, so one bug does not leak anything:

1. Allowlist. A finding is rebuilt from a fixed set of structured fields. Code
   snippets, secret values and scanner evidence were already dropped by
   fortress.normalize; anything else a scanner adds later is ignored here too.
   Findings in the "secrets" category are never sent at all.
2. Pseudonymisation. File paths, e-mail addresses, hostnames, URLs and IPs are
   replaced by stable tokens (PATH_1, EMAIL_1, ...). The mapping stays on the
   runner and is used to translate the model's answer back.
3. Fail-closed guard. The final serialised payload is scanned for secret
   patterns, high-entropy tokens and code. Any hit raises RedactionError and
   nothing is sent.

Every payload that passes is written byte-for-byte to an audit directory, so
"no secret or source code reached the LLM" can be checked after the fact.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

ALLOWED_FIELDS = ("id", "tool", "category", "rule_id", "title", "severity", "cwe", "cve",
                  "package", "installed_version", "fixed_version", "file", "line")
NEVER_SEND_CATEGORIES = {"secrets"}

_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_URL = re.compile(r"\bhttps?://[^\s'\"<>)]+")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HOST = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:internal|corp|local|lan|intranet)\b", re.I)

# Patterns that must never appear in an outbound payload, whatever the field.
_SECRET_PATTERNS = {
    "private-key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "aws-access-key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "github-token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "google-api-key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "slack-token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    "bearer": re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]{16,}", re.I),
    "assignment": re.compile(r"(?i)\b(?:password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*['\"][^'\"]{6,}"),
}
# Shapes of source code: statements, blocks, template literals, SQL.
_CODE_PATTERNS = {
    "fenced-block": re.compile(r"```"),
    "statement": re.compile(r"[;{}]\s*$|=>\s*\{", re.M),
    "template-literal": re.compile(r"`[^`]*\$\{"),
    "sql": re.compile(r"(?i)\b(?:select\s+[\w*,\s]+\s+from|insert\s+into|update\s+\w+\s+set|delete\s+from)\b"),
    "call-chain": re.compile(r"\b\w+\.\w+\([^)]*\)\.\w+\("),
}
_TOKEN = re.compile(r"[A-Za-z0-9+/_=-]{24,}")
# Values that look random but are known-safe identifiers in this payload.
_SAFE_TOKEN = re.compile(r"^(?:CVE-\d{4}-\d+|GHSA(?:-[a-z0-9]{4}){3}|CKV2?_[A-Z0-9_]+|[a-f0-9]{12})$")


class RedactionError(Exception):
    """Raised when a payload still contains something that must not leave the runner."""


def shannon_entropy(text: str) -> float:
    counts = Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


@dataclass
class Pseudonymiser:
    """Stable, reversible token mapping. Lives only in memory on the runner."""
    forward: dict[str, str] = field(default_factory=dict)
    counters: Counter = field(default_factory=Counter)

    def token(self, kind: str, value: str) -> str:
        if value not in self.forward:
            self.counters[kind] += 1
            self.forward[value] = f"{kind}_{self.counters[kind]}"
        return self.forward[value]

    def path(self, value: str | None) -> str | None:
        if not value:
            return value
        if value not in self.forward:
            # Keep the extension: it tells the model the language without naming anything.
            suffix = Path(value).suffix
            self.counters["PATH"] += 1
            self.forward[value] = f"PATH_{self.counters['PATH']}" + (suffix if re.fullmatch(r"\.[A-Za-z0-9]{1,5}", suffix) else "")
        return self.forward[value]

    def text(self, value: str) -> str:
        value = _EMAIL.sub(lambda m: self.token("EMAIL", m.group(0)), value)
        value = _URL.sub(lambda m: self.token("URL", m.group(0)), value)
        value = _IPV4.sub(lambda m: self.token("IP", m.group(0)), value)
        return _HOST.sub(lambda m: self.token("HOST", m.group(0)), value)

    def restore(self, value: str) -> str:
        """Translate tokens in model output back to real identifiers (longest first)."""
        for real, tok in sorted(self.forward.items(), key=lambda kv: -len(kv[1])):
            base, dot, ext = tok.partition(".")
            pattern = rf"\b{re.escape(base)}(?:\.{re.escape(ext)})?\b" if dot else rf"\b{re.escape(tok)}\b"
            value = re.sub(pattern, lambda _m, r=real: r, value)
        return value


def minimise(finding: dict, ps: Pseudonymiser) -> dict:
    out = {k: finding.get(k) for k in ALLOWED_FIELDS if finding.get(k) not in (None, [], "")}
    if "file" in out:
        out["file"] = ps.path(out["file"])
    if "title" in out:
        out["title"] = ps.text(str(out["title"]))[:200]
    return out


def _strings(data: object):
    if isinstance(data, str):
        yield data
    elif isinstance(data, dict):
        for k, v in data.items():
            yield str(k)
            yield from _strings(v)
    elif isinstance(data, (list, tuple)):
        for v in data:
            yield from _strings(v)


def scan_payload(*parts: object) -> list[str]:
    """Reasons the given prompt/data must not be sent (empty list = safe).

    Every string value is checked on its own, so JSON punctuation around the
    values is never mistaken for source code.
    """
    problems: set[str] = set()
    for text in (t for part in parts for t in _strings(part)):
        problems |= {f"secret:{n}" for n, rx in _SECRET_PATTERNS.items() if rx.search(text)}
        problems |= {f"code:{n}" for n, rx in _CODE_PATTERNS.items() if rx.search(text)}
        problems |= {f"identifier:{n}" for n, rx in (("email", _EMAIL), ("url", _URL), ("ip", _IPV4), ("host", _HOST))
                     if rx.search(text)}
        # Random credentials mix letters and digits; hyphenated header names
        # such as Cross-Origin-Embedder-Policy are long and varied but have no digit.
        if any(not _SAFE_TOKEN.match(t) and re.search(r"\d", t) and re.search(r"[A-Za-z]", t)
               and shannon_entropy(t) > 4.0 for t in _TOKEN.findall(text)):
            problems.add("secret:high-entropy-token")
    return sorted(problems)


@dataclass
class Redactor:
    audit_dir: Path | None = None
    ps: Pseudonymiser = field(default_factory=Pseudonymiser)
    sent: int = 0
    withheld: list[dict] = field(default_factory=list)

    def prepare(self, findings: list[dict]) -> list[dict]:
        """Minimise and pseudonymise; findings that must never leave are set aside."""
        out = []
        for f in findings:
            if f.get("category") in NEVER_SEND_CATEGORIES:
                self.withheld.append(f)
                continue
            out.append(minimise(f, self.ps))
        return out

    def seal(self, prompt: str, data: object) -> str:
        """Serialise the outbound request body, verify it, and record it in the audit log."""
        problems = scan_payload(prompt, data)
        if problems:
            raise RedactionError("payload withheld: " + ", ".join(problems))
        payload = prompt + "\n\nDATA:\n" + json.dumps(data, indent=1, sort_keys=True)
        if self.audit_dir:
            self.audit_dir.mkdir(parents=True, exist_ok=True)
            self.sent += 1
            digest = hashlib.sha256(payload.encode()).hexdigest()[:12]
            (self.audit_dir / f"{self.sent:03d}-{digest}.txt").write_text(payload)
        return payload
