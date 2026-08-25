#!/usr/bin/env python3
"""
audit-dashboard.py — per-repo pre-deploy contamination check.

Run from the dashboard repo root:
  python3 audit-dashboard.py

Exit code 0 = clean (safe to deploy).
Exit code 1 = bugs found (DO NOT DEPLOY).

This script catches the contamination classes Vince hit on 2026-06-17:
  - Wrong APP_ID (cross-dashboard localStorage collision)
  - Stale grant ID refs in deadlineItems / rationales (FCB incident)
  - Title/H1 leftover from forked template
  - Unbalanced <script> tags or syntax-broken JS (propagate2.sh incident)
  - Half-applied propagation blocks

Mandated by feedback_template_contamination_audit + feedback_cross_family_
propagation_safety memories. Do not skip.
"""
import re, sys, json, subprocess, tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
INDEX = REPO_ROOT / "index.html"
DIRNAME = REPO_ROOT.name

# Markers expected on a complete dashboard. If a marker exists, its END must too.
REQUIRED_MARKER_PAIRS = [
    # (start_substring, end_substring, label)
    ("REPORTING-V1-JS — ",     "REPORTING-V1-JS — end",     "REPORTING-V1-JS"),
    ("REPORTING-V2-CSS",       "REPORTING-V2-CSS — end",    "REPORTING-V2-CSS"),
    ("REPORTING-V2-JS — ",     "REPORTING-V2-JS — end",     "REPORTING-V2-JS"),
    ("REPORTING-V3-CSS",       "REPORTING-V3-CSS — end",    "REPORTING-V3-CSS"),
    ("REPORTING-V3-JS — ",     "REPORTING-V3-JS — end",     "REPORTING-V3-JS"),
    ("STEWARDSHIP-V1-JS — ",   "STEWARDSHIP-V1-JS — end",   "STEWARDSHIP-V1-JS"),
]

ID_PATTERN     = re.compile(r'(?:id|grantId|grant_id)\s*:\s*["\']([A-Z]{2,5}-\d{3,4})["\']')
KEY_PATTERN    = re.compile(r'["\']([A-Z]{2,5}-\d{3,4})["\']\s*:')
GRANTS_ARRAY   = re.compile(r'const\s+grants\s*=\s*\[(.*?)\];\s*(?:const|let|var|window|function)', re.DOTALL)
DEADLINE_ARRAY = re.compile(r'(?:const|let|var)\s+deadlineItems\s*=\s*\[(.*?)\];', re.DOTALL)
RATIONALES_OBJ = re.compile(r'(?:const|let|var)\s+rationales\s*=\s*\{(.*?)\};', re.DOTALL)
APP_ID_PATTERN = re.compile(r"const\s+APP_ID\s*=\s*['\"]([^'\"]+)['\"]")
TITLE_PATTERN  = re.compile(r"<title>([^<]+)</title>", re.IGNORECASE)
SCRIPT_OPEN    = re.compile(r"<script\b")

class Result:
    def __init__(self):
        self.errors = []
        self.warnings = []
    def err(self, msg): self.errors.append(msg)
    def warn(self, msg): self.warnings.append(msg)

def check_html_exists(r):
    if not INDEX.exists():
        r.err(f"no index.html in {REPO_ROOT}")
        return None
    return INDEX.read_text(encoding="utf-8")

def check_appid(src, r):
    m = APP_ID_PATTERN.search(src)
    if not m:
        r.warn("no APP_ID constant found (dashboard may use a different key naming convention)")
        return
    appid = m.group(1)
    if appid != DIRNAME:
        r.err(f"APP_ID mismatch: code says '{appid}', repo dir is '{DIRNAME}' "
              f"(localStorage will collide with the dashboard whose dir matches the APP_ID)")

def check_grant_ids(src, r):
    gm = GRANTS_ARRAY.search(src)
    if not gm:
        gm = re.search(r'const\s+grants\s*=\s*\[(.*)$', src, re.DOTALL)
    if not gm:
        return  # no grants array — skip
    grants_text = gm.group(1)[:80000]
    canonical = set(ID_PATTERN.findall(grants_text))

    dm = DEADLINE_ARRAY.search(src)
    if dm:
        deadline_ids = set(ID_PATTERN.findall(dm.group(1)))
        stale = sorted(deadline_ids - canonical)
        if stale:
            r.err(f"deadlineItems references grant IDs not in grants array: {stale[:6]}"
                  + (f" (and {len(stale)-6} more)" if len(stale) > 6 else ""))

    rm = RATIONALES_OBJ.search(src)
    if rm:
        rationale_ids = set(KEY_PATTERN.findall(rm.group(1)))
        stale = sorted(rationale_ids - canonical)
        if stale:
            r.err(f"rationales has grant IDs not in grants array: {stale[:6]}"
                  + (f" (and {len(stale)-6} more)" if len(stale) > 6 else ""))

def check_title(src, r):
    m = TITLE_PATTERN.search(src)
    if not m:
        r.warn("no <title> tag found")
        return
    title = m.group(1).strip()
    # Soft check: the title should be more than the generic "Bothy Dashboard" fragment alone
    if title in ("Bothy Dashboard", "Grant Dashboard", "Bothy"):
        r.err(f"title is generic ('{title}') — may be a leftover from a forked template")

def check_script_balance(src, r):
    open_count = len(SCRIPT_OPEN.findall(src))
    close_count = src.count("</script>")
    if open_count != close_count:
        r.err(f"unbalanced <script> tags: {open_count} open vs {close_count} close")

def check_markers(src, r):
    for start_sub, end_sub, label in REQUIRED_MARKER_PAIRS:
        has_start = start_sub in src
        has_end = end_sub in src
        if has_start and not has_end:
            r.err(f"marker {label}: opened but no end marker — half-applied block")
        elif has_end and not has_start:
            r.err(f"marker {label}: end marker present but no opening — corrupted block")

def check_js_syntax(src, r):
    # Extract each <script>...</script> and pipe to `node --check`.
    # We use a simple state machine to avoid greedy regex disasters.
    scripts = []
    i = 0
    while True:
        start = src.find("<script", i)
        if start < 0: break
        gt = src.find(">", start)
        if gt < 0: break
        end = src.find("</script>", gt)
        if end < 0:
            r.err("unterminated <script> tag")
            return
        attrs = src[start:gt].lower()
        # Only JS gets node --check: skip data islands (application/json,
        # ld+json) and any other non-JS script type.
        is_js = ("type=" not in attrs) or ("javascript" in attrs) or ("module" in attrs)
        if is_js:
            scripts.append(src[gt+1:end])
        i = end + len("</script>")
    for idx, body in enumerate(scripts):
        if not body.strip(): continue
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
            f.write(body); path = f.name
        try:
            cp = subprocess.run(["node", "--check", path], capture_output=True, text=True)
            if cp.returncode != 0:
                # Show first error line
                msg = (cp.stderr or "").splitlines()
                msg = " ".join(msg[:2]) if msg else "(no stderr)"
                r.err(f"<script> #{idx+1} has JS syntax error: {msg[:200]}")
        except FileNotFoundError:
            r.warn("node not found in PATH — skipping JS syntax check")
            return
        finally:
            Path(path).unlink(missing_ok=True)

def check_nav_consistency(src, r):
    # Catch the runtime-crash class where showSection('id') is called with an id that
    # isn't safely reachable. Observed on active-heroes: 'start' was missing from
    # tabOrder while showSection did an UNGUARDED tabs[tabOrder.indexOf(id)] — so
    # indexOf returned -1, tabs[-1] was undefined, and .classList threw at load. That
    # uncaught error ran before the first-visit flag was saved, so it re-fired every
    # visit and halted init before updateHeroUrgent() ran — leaving the hero blank.
    # node --check can't see this (it's runtime, not syntax); verify it statically.
    # reporting/crm/outcomes/narrative are injected at runtime (STEWARDSHIP-V2 etc.)
    # and extended into tabOrder then — they legitimately aren't in the static HTML,
    # so exclude them to avoid false positives; only CORE nav tabs are checked.
    RUNTIME_TABS = {"reporting", "crm", "outcomes", "narrative"}
    call_ids = sorted(set(re.findall(r"showSection\(['\"]([a-z0-9-]+)['\"]\)", src)) - RUNTIME_TABS)
    if not call_ids:
        return
    tm = re.search(r"tabOrder\s*=\s*\[([^\]]*)\]", src)
    tab_ids = [t.strip().strip("'\"") for t in tm.group(1).split(",") if t.strip()] if tm else None
    # The guarded template uses `const x = ...; if(x) x.classList`; only flag the
    # UNGUARDED direct-access forms that actually throw.
    unguarded_tab = bool(re.search(r"querySelectorAll\(['\"]\.tab['\"]\)\[tabOrder\.indexOf\(id\)\]\.classList", src))
    unguarded_sec = bool(re.search(r"getElementById\(id\)\.classList\.add", src))
    if unguarded_tab and tab_ids is not None:
        missing = [i for i in call_ids if i not in tab_ids]
        if missing:
            r.err(f"showSection target(s) {missing} not in tabOrder while the tab lookup is "
                  f"unguarded — tabOrder.indexOf()->-1->tabs[-1].classList throws at load "
                  f"(halts init; blanks the Next-Deadline hero). Add them to tabOrder or guard showSection.")
    if unguarded_sec:
        missing_el = [i for i in call_ids if f'id="{i}"' not in src]
        if missing_el:
            r.err(f"showSection target(s) {missing_el} have no matching section element — "
                  f"getElementById()->null->.classList throws at load. Add the section or guard showSection.")

def main():
    r = Result()
    src = check_html_exists(r)
    if src is None:
        print_report(r); sys.exit(1)
    check_appid(src, r)
    check_grant_ids(src, r)
    check_title(src, r)
    check_script_balance(src, r)
    check_markers(src, r)
    check_js_syntax(src, r)
    check_nav_consistency(src, r)
    print_report(r)
    sys.exit(1 if r.errors else 0)

def print_report(r):
    print(f"audit-dashboard.py — {DIRNAME}")
    print("=" * 60)
    if r.errors:
        print(f"\n  {len(r.errors)} ERROR(S):")
        for e in r.errors: print(f"    🚨 {e}")
    if r.warnings:
        print(f"\n  {len(r.warnings)} warning(s):")
        for w in r.warnings: print(f"    ⚠️  {w}")
    if not r.errors and not r.warnings:
        print("\n  ✅ All checks passed.")
    elif not r.errors:
        print("\n  ✅ No errors. Warnings non-blocking.")
    else:
        print(f"\n  ❌ {len(r.errors)} error(s) — DO NOT DEPLOY until fixed.")
    print()

if __name__ == "__main__":
    main()
