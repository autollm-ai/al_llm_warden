"""Destructive Command Guard — a third scanning pipeline.

Inspired by github.com/Dicklesworthstone/destructive_command_guard. Runs
alongside the tier-1 secret/PII regex engine and flags destructive shell,
git, database, container, kubernetes, cloud and IaC commands embedded in
outbound LLM prompts.

Pipeline (per body):
  1. Quick-reject substring filter — if none of a small set of trigger
     keywords ("rm ", "git ", "drop ", …) appear, skip the regex pass.
  2. Safe-pattern allowlist — `git checkout -b`, `git clean --dry-run`,
     `rm -rf /tmp/*`, etc. Any destructive match whose span overlaps a
     safe span is suppressed.
  3. Destructive pattern matching — severity-weighted regexes grouped by
     domain, scored on the same saturating-sum scale as regex_engine.

Hits are returned as `regex_engine.RegexHit` so they flow through the
existing classifier, database schema and dashboard untouched. Their
`category` is namespaced as ``destructive:<domain>`` (e.g.
``destructive:git``) so the UI can distinguish them from secret/PII
findings.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .regex_engine import RegexHit


@dataclass(frozen=True)
class DCGPattern:
    name: str
    regex: re.Pattern[str]
    severity: str   # "error" | "warning"
    domain: str     # "git" | "filesystem" | "database" | …


# Severity → tier-1 weight in [0, 1]. Same scale as regex_engine.
_SEVERITY_WEIGHT = {"error": 0.9, "warning": 0.6}

# Quick-reject keywords (lowercase). If none appear in the body we skip
# the entire pass. Cheap O(n) `in` checks keep the hot path well under
# a microsecond on typical prompts.
_KEYWORDS: tuple[str, ...] = (
    "rm ", "rm\t", "rm\n", "dd ", "mkfs", "chmod ", "shred",
    "git ", "docker", "kubectl", "helm ", "terraform",
    "drop ", "truncate", "delete from", "flushall", "flushdb",
    "aws ", ":(){",
)

# Safe patterns shadow destructive matches in the same span — they're the
# allowlist of well-known non-destructive idioms that share keywords with
# the dangerous ones (e.g. `git checkout -b feat` vs `git checkout --`).
_SAFE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bgit\s+checkout\s+-b\b"),
    re.compile(r"\bgit\s+checkout\s+--orphan\b"),
    re.compile(r"\bgit\s+restore\s+(?:--staged|-S)\b"),
    re.compile(r"\bgit\s+clean\s+(?:-[a-zA-Z]*n[a-zA-Z]*|--dry-run)\b"),
    re.compile(
        r"\brm\s+-[rRfF]+\s+"
        r"(?:/tmp/|/var/tmp/|\$TMPDIR/|\$\{TMPDIR\}/|"
        r"\./node_modules|\./dist|\./build|\./target|\./\.next|\./\.cache)"
        r"\S*"
    ),
    re.compile(r"\bkubectl\s+delete\s+(?:pod|po|job|cronjob)\b"),  # routine
]


PATTERNS: list[DCGPattern] = [
    # ── Filesystem (catastrophic) ────────────────────────────────────────
    DCGPattern(
        "rm_rf_root",
        re.compile(r"\brm\s+(?:-[a-zA-Z]*[rRfF][a-zA-Z]*\s+)+(?:--no-preserve-root\s+)?/(?:\s|$|\*)"),
        "error", "filesystem",
    ),
    DCGPattern(
        "rm_rf_home",
        re.compile(r"\brm\s+-[a-zA-Z]*[rRfF][a-zA-Z]*\s+(?:~/?(?:\s|$)|\$HOME\b|/home/\S+)"),
        "error", "filesystem",
    ),
    DCGPattern(
        "dd_to_disk",
        re.compile(r"\bdd\s+(?:[\w=./\-]+\s+)*of=/dev/(?:sd[a-z]|nvme\d|hd[a-z]|disk\d|mmcblk\d)"),
        "error", "filesystem",
    ),
    DCGPattern(
        "mkfs_on_device",
        re.compile(r"\bmkfs(?:\.\w+)?\s+/dev/"),
        "error", "filesystem",
    ),
    DCGPattern(
        "fork_bomb",
        re.compile(r":\(\)\s*\{\s*:\s*\|\s*:?\s*&\s*\}\s*;\s*:"),
        "error", "filesystem",
    ),
    DCGPattern(
        "chmod_recursive_root",
        re.compile(r"\bchmod\s+-R\s+\d{3,4}\s+/(?:\s|$)"),
        "error", "filesystem",
    ),
    DCGPattern(
        "shred_recursive",
        re.compile(r"\bshred\s+-[a-zA-Z]*[uz][a-zA-Z]*\b"),
        "warning", "filesystem",
    ),
    DCGPattern(
        "rm_rf_generic",
        re.compile(r"\brm\s+-[a-zA-Z]*[rR][a-zA-Z]*[fF][a-zA-Z]*\b|\brm\s+-[a-zA-Z]*[fF][a-zA-Z]*[rR][a-zA-Z]*\b"),
        "warning", "filesystem",
    ),

    # ── Git ──────────────────────────────────────────────────────────────
    DCGPattern(
        "git_reset_hard",
        re.compile(r"\bgit\s+reset\s+--hard\b"),
        "warning", "git",
    ),
    DCGPattern(
        "git_push_force",
        re.compile(r"\bgit\s+push\s+(?:-f\b|--force(?:-with-lease)?\b)"),
        "warning", "git",
    ),
    DCGPattern(
        "git_clean_force",
        re.compile(r"\bgit\s+clean\s+-[a-zA-Z]*[fdxFDX][a-zA-Z]*\b"),
        "warning", "git",
    ),
    DCGPattern(
        "git_branch_force_delete",
        re.compile(r"\bgit\s+branch\s+-D\b"),
        "warning", "git",
    ),
    DCGPattern(
        "git_stash_destroy",
        re.compile(r"\bgit\s+stash\s+(?:drop|clear)\b"),
        "warning", "git",
    ),
    DCGPattern(
        "git_checkout_discard",
        re.compile(r"\bgit\s+checkout\s+--\s+\S"),
        "warning", "git",
    ),

    # ── Database ─────────────────────────────────────────────────────────
    DCGPattern(
        "sql_drop_database",
        re.compile(r"(?i)\bDROP\s+DATABASE\b"),
        "error", "database",
    ),
    DCGPattern(
        "sql_drop_table",
        re.compile(r"(?i)\bDROP\s+TABLE\b"),
        "warning", "database",
    ),
    DCGPattern(
        "sql_truncate",
        re.compile(r"(?i)\bTRUNCATE\s+(?:TABLE\s+)?\w+"),
        "warning", "database",
    ),
    DCGPattern(
        "sql_delete_no_where",
        re.compile(r"(?i)\bDELETE\s+FROM\s+\w+\s*(?:;|$)", re.MULTILINE),
        "warning", "database",
    ),
    DCGPattern(
        "redis_flush",
        re.compile(r"\b(?:redis-cli\s+(?:-\w+\s+)*)?FLUSH(?:ALL|DB)\b"),
        "error", "database",
    ),
    DCGPattern(
        "mongo_drop_database",
        re.compile(r"\bdb\.dropDatabase\(\s*\)"),
        "error", "database",
    ),
    DCGPattern(
        "mongo_drop_collection",
        re.compile(r"\bdb\.\w+\.drop\(\s*\)"),
        "warning", "database",
    ),

    # ── Containers ───────────────────────────────────────────────────────
    DCGPattern(
        "docker_system_prune",
        re.compile(r"\bdocker\s+system\s+prune\b"),
        "warning", "container",
    ),
    DCGPattern(
        "docker_volume_destroy",
        re.compile(r"\bdocker\s+volume\s+(?:prune|rm)\b"),
        "warning", "container",
    ),
    DCGPattern(
        "docker_rm_force",
        re.compile(r"\bdocker\s+rm\s+-[a-zA-Z]*f[a-zA-Z]*\s"),
        "warning", "container",
    ),

    # ── Kubernetes ───────────────────────────────────────────────────────
    DCGPattern(
        "kubectl_delete_namespace",
        re.compile(r"\bkubectl\s+delete\s+(?:ns|namespace)s?\b"),
        "error", "kubernetes",
    ),
    DCGPattern(
        "kubectl_delete_pv",
        re.compile(r"\bkubectl\s+delete\s+(?:pv|persistentvolume)s?\b"),
        "error", "kubernetes",
    ),
    DCGPattern(
        "kubectl_drain",
        re.compile(r"\bkubectl\s+drain\b"),
        "warning", "kubernetes",
    ),
    DCGPattern(
        "helm_uninstall",
        re.compile(r"\bhelm\s+(?:uninstall|delete)\b"),
        "warning", "kubernetes",
    ),

    # ── Cloud / IaC ──────────────────────────────────────────────────────
    DCGPattern(
        "terraform_destroy",
        re.compile(r"\bterraform\s+destroy\b"),
        "error", "iac",
    ),
    DCGPattern(
        "terraform_auto_approve",
        re.compile(r"\bterraform\s+apply\s+(?:[^\n]*\s)?-auto-approve\b"),
        "warning", "iac",
    ),
    DCGPattern(
        "aws_s3_remove_bucket",
        re.compile(r"\baws\s+s3\s+rb\s+s3://\S+\s+--force\b"),
        "error", "cloud",
    ),
    DCGPattern(
        "aws_terminate_instances",
        re.compile(r"\baws\s+ec2\s+terminate-instances\b"),
        "error", "cloud",
    ),
    DCGPattern(
        "aws_rds_delete",
        re.compile(r"\baws\s+rds\s+delete-db-instance\b"),
        "error", "cloud",
    ),
]


def _quick_reject(text_lower: str) -> bool:
    return not any(kw in text_lower for kw in _KEYWORDS)


def _safe_spans(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for sp in _SAFE_PATTERNS:
        spans.extend(m.span() for m in sp.finditer(text))
    return spans


def _overlaps(span: tuple[int, int], spans: list[tuple[int, int]]) -> bool:
    a, b = span
    for sa, sb in spans:
        if a < sb and sa < b:
            return True
    return False


def _snippet(raw: str) -> str:
    """Show the matched command verbatim, truncated for storage."""
    raw = raw.strip()
    if len(raw) <= 120:
        return raw
    return raw[:80] + "…" + raw[-30:]


def scan(text: str, max_hits: int = 50) -> tuple[list[RegexHit], float]:
    """Run the destructive-command guard.

    Returns (hits, score) where score is in [0, 1] using the same
    saturating-sum scale as regex_engine.scan() so the two pipelines can
    be combined directly.
    """
    if not text:
        return [], 0.0
    if _quick_reject(text.lower()):
        return [], 0.0

    safe = _safe_spans(text)
    hits: list[RegexHit] = []
    score = 0.0
    for p in PATTERNS:
        for m in p.regex.finditer(text):
            if len(hits) >= max_hits:
                break
            sp = m.span()
            if _overlaps(sp, safe):
                continue
            weight = _SEVERITY_WEIGHT[p.severity]
            hits.append(RegexHit(
                name=p.name,
                category=f"destructive:{p.domain}",
                weight=weight,
                snippet=_snippet(m.group(0)),
                span=sp,
            ))
            score = score + weight * (1.0 - score) * 0.6
    return hits, min(score, 1.0)
