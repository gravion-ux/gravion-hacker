"""Bug bounty workflow helpers: checklists and report drafting (no auto-submit)."""

from __future__ import annotations

SEVEN_QUESTION_GATE = [
    "Is the target explicitly in scope for this program?",
    "Is the vulnerability class accepted by the program?",
    "Can I reproduce it reliably in my lab or on my own test account?",
    "Is the impact real and demonstrable without harming other users?",
    "Have I checked for duplicates in public disclosures and program history?",
    "Is the evidence minimal, redacted and free of other users' data?",
    "Would I be comfortable explaining every step to the program team?",
]

DEDUPE_CHECKLIST = [
    "Search the program's disclosed reports for the same endpoint and class.",
    "Search public CVE/advisory databases for the same product and class.",
    "Check vendor changelogs for a recent fix of the same issue.",
    "Check my own previous submissions for overlap.",
    "Confirm the affected version is the latest in-scope version.",
]

SCOPE_CHECKLIST = [
    "Program scope and exclusions re-read today.",
    "Testing window and rate limits noted.",
    "Only my own accounts/data used for proof.",
    "No denial-of-service, spam or social-engineering methods.",
    "Stop conditions and emergency contact noted.",
]


def report_draft(
    *,
    title: str,
    program: str,
    asset: str,
    severity: str,
    summary: str,
    steps: list[str],
    impact: str,
    remediation: str,
) -> str:
    steps_md = "\n".join(f"{i}. {step}" for i, step in enumerate(steps, 1))
    return (
        f"# {title}\n\n"
        f"**Program:** {program}\n\n"
        f"**Asset:** {asset}\n\n"
        f"**Severity:** {severity}\n\n"
        f"## Summary\n\n{summary}\n\n"
        f"## Steps to reproduce (authorized test account / local lab)\n\n{steps_md}\n\n"
        f"## Impact\n\n{impact}\n\n"
        f"## Remediation\n\n{remediation}\n\n"
        "## Notes\n\n"
        "Testing was performed only within the authorized scope above. "
        "No other users' data was accessed. This draft is for manual review and submission by the researcher.\n"
    )
