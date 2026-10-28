from fortress import dashboard

from .test_normalize_gate import POLICY, all_findings

RUN = {"id": 1, "run_number": 7, "html_url": "https://example.invalid/run/1",
       "head_sha": "abcdef1234567", "created_at": "2026-10-28T10:00:00Z"}
JOBS = [
    {"name": "Secrets (gitleaks)", "started_at": "2026-10-28T10:00:05Z",
     "completed_at": "2026-10-28T10:00:20Z", "conclusion": "success"},
    {"name": "Security gate (pre-build)", "started_at": "2026-10-28T10:01:00Z",
     "completed_at": "2026-10-28T10:01:12Z", "conclusion": "success"},
    {"name": "Consolidate findings", "started_at": "2026-10-28T10:09:00Z",
     "completed_at": None, "conclusion": None},
]


def test_renders_every_stage_and_the_verdict_time():
    html = dashboard.render(all_findings(), None, POLICY, RUN, JOBS, None, None)
    for _, label in dashboard.STAGES:
        assert f">{label}</text>" in html
    assert "1m 12s" in html  # push -> pre-build gate verdict
    assert "Consolidate findings" not in html  # unfinished jobs are skipped


def test_untrusted_text_is_escaped():
    jobs = JOBS + [{"name": "<img src=x onerror=alert(1)>", "started_at": "2026-10-28T10:00:01Z",
                    "completed_at": "2026-10-28T10:00:02Z", "conclusion": "success"}]
    seeded = [{"title": "<script>alert(1)</script>", "expected": "sast", "caught_by": ["sast"],
               "blocked": True, "url": "javascript:alert(1)\" onmouseover=\"x"}]
    html = dashboard.render(all_findings(), None, POLICY, RUN, jobs, seeded, None)
    assert "<script>alert(1)" not in html
    assert "<img src=x" not in html
    assert '" onmouseover="' not in html


def test_catch_rate_compares_against_target():
    seeded = [{"title": f"seed {i}", "expected": "sast", "caught_by": ["sast"] if i < 4 else [],
               "blocked": i < 3} for i in range(5)]
    html = dashboard.render(all_findings(), None, POLICY, None, [], seeded, None)
    assert "80%" in html and "4 of 5" in html
    assert "Missed" in html
