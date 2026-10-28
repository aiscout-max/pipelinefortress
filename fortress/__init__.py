"""PipelineFortress: scanner normalisation, security gates and GenAI triage."""

SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def severity_rank(severity: str) -> int:
    return SEVERITIES.index(severity) if severity in SEVERITIES else 0
