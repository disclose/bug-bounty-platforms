#!/usr/bin/env python3
"""Daily liveness check for the bug-bounty-platforms catalog.

Walks the README table, extracts every platform data URL (homepage, leaderboard,
public-programs), and checks that each still resolves. Bot-gated responses
(any 4xx except 404/410) count as ALIVE — the host answered, it just gates
automation. Only DNS failure, connection refused, timeout, 404/410, TLS failure,
and persistent 5xx are DEAD.

Fetching is done with `curl`, not urllib: some hosts fingerprint and reset a
bare Python TLS handshake (or answer it with a 500) while serving real browsers
and curl a clean 200. Using curl makes the check reflect what a human actually
sees and avoids flagging live platforms as dead.

Twitter/X handles (README column 4) are deliberately never checked: x.com
throttles automated clients and its failures carry no signal about liveness.

Standard library only — the same zero-dependency footprint as validate-table.yml,
so GitHub's ubuntu-latest runner needs no `pip install` (curl is preinstalled).
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlparse

# README table layout (0-indexed cells after splitting on '|'):
#   0 Platform Name | 1 URL | 2 Region | 3 Twitter/X | 4 Program Types
#   5 Has Leaderboard | 6 Leaderboard URL | 7 Public Programs URL
EXPECTED_COLUMNS = 8
URL_COLUMNS = {1: "Homepage", 6: "Leaderboard", 7: "Public Programs"}

# Hosts whose automated failures are noise, not signal.
EXCLUDED_HOSTS = ("x.com", "twitter.com", "t.co")

BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0 Safari/537.36 "
    "(disclose.io-platform-liveness-check; +https://github.com/disclose/bug-bounty-platforms)"
)

# Resources that are genuinely gone — DEAD even though the host answered.
DEAD_STATUS = {404, 410}

# curl exit codes we can name in the report.
CURL_ERRORS = {
    6: "DNS resolution failed",
    7: "connection refused",
    28: "timed out",
    35: "TLS handshake failed",
    51: "TLS certificate mismatch",
    56: "connection reset",
    60: "TLS certificate error",
}

MARKDOWN_LINK = re.compile(r"\((https?://[^)\s]+)\)")
BARE_URL = re.compile(r"(https?://[^\s|)\]]+)")


def extract_url(cell: str) -> str | None:
    """Pull the bare URL out of a `[text](url)` markdown cell (or a bare URL)."""
    m = MARKDOWN_LINK.search(cell)
    if m:
        return m.group(1)
    m = BARE_URL.search(cell)
    return m.group(1) if m else None


def parse_targets(readme_path: str) -> list[dict]:
    """Return de-duplicated {url, platforms:[(name,column)]} targets from the README."""
    text = open(readme_path, encoding="utf-8").read()
    by_url: dict[str, dict] = {}
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) != EXPECTED_COLUMNS:
            continue
        if cells[0] == "Platform Name" or set(cells[0]) == {"-"}:
            continue
        name = cells[0]
        for idx, label in URL_COLUMNS.items():
            url = extract_url(cells[idx])
            if not url:
                continue
            host = (urlparse(url).hostname or "").lower()
            if host.startswith("www."):
                host = host[4:]
            if host in EXCLUDED_HOSTS:
                continue
            entry = by_url.setdefault(url, {"url": url, "platforms": []})
            entry["platforms"].append((name, label))
    return list(by_url.values())


def check_once(url: str, timeout: int) -> tuple[str, str]:
    """One curl attempt. Returns (verdict, detail) with verdict in ALIVE/DEAD."""
    try:
        proc = subprocess.run(
            [
                "curl", "-sS", "-o", os.devnull, "-L",
                "--max-time", str(timeout),
                # Damp transient blips within a single run: 3 attempts total on
                # timeouts / 5xx / connection-refused, so a momentary hiccup does
                # not flap a live platform into the dead list.
                "--retry", "2",
                "--retry-connrefused",
                "--retry-delay", "2",
                "-A", BROWSER_UA,
                "-w", "%{http_code}",
                url,
            ],
            capture_output=True,
            text=True,
            timeout=timeout + 10,
        )
    except subprocess.TimeoutExpired:
        return ("DEAD", "timed out")

    if proc.returncode == 0:
        try:
            code = int((proc.stdout or "").strip()[:3])
        except ValueError:
            return ("DEAD", f"no HTTP status ({proc.stdout!r})")
        if code == 0:
            return ("DEAD", "no response")
        if code in DEAD_STATUS or code >= 500:
            return ("DEAD", f"HTTP {code}")
        if 400 <= code < 500:
            return ("ALIVE", f"HTTP {code} (gated)")
        return ("ALIVE", f"HTTP {code}")

    return ("DEAD", CURL_ERRORS.get(proc.returncode, f"curl error {proc.returncode}"))


def is_transient(detail: str) -> bool:
    """Timeouts, resets, and 5xx are worth one retry; DNS/404/TLS are not."""
    return detail.startswith("HTTP 5") or "timed out" in detail or "reset" in detail


def check(url: str, timeout: int, retries: int) -> tuple[str, str]:
    """Check a URL, retrying transient DEAD verdicts before giving up."""
    verdict, detail = check_once(url, timeout)
    attempt = 0
    while verdict == "DEAD" and attempt < retries and is_transient(detail):
        time.sleep(2)
        attempt += 1
        verdict, detail = check_once(url, timeout)
    return verdict, detail


def build_report(results: list[dict], targets: int, platforms: int) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    dead = [r for r in results if r["verdict"] == "DEAD"]
    alive = len(results) - len(dead)
    lines = [
        "# Catalog link liveness report",
        "",
        f"_Last run: {now}_",
        "",
        f"- **{targets}** unique URLs checked across **{platforms}** platform table cells",
        f"- **{alive}** alive · **{len(dead)}** dead",
        "",
    ]
    if not dead:
        lines.append("All catalog links resolved. Nothing to fix. ✅")
        return "\n".join(lines) + "\n"

    lines += [
        f"## {len(dead)} link(s) need attention",
        "",
        "Bot-gated responses (401/403/405/429, etc.) are reported as alive, so every row"
        " below is a genuine failure — a dead domain, a moved page, a TLS break, or a"
        " server error. Confirm in a browser before editing the catalog.",
        "",
        "| Platform | Column | URL | Status |",
        "|----------|--------|-----|--------|",
    ]
    for r in sorted(dead, key=lambda x: x["platforms"][0][0].lower()):
        for name, label in r["platforms"]:
            lines.append(f"| {name} | {label} | {r['url']} | {r['detail']} |")
    lines.append("")
    return "\n".join(lines) + "\n"


def write_github_output(dead_count: int) -> None:
    out = os.environ.get("GITHUB_OUTPUT")
    if not out:
        return
    with open(out, "a", encoding="utf-8") as fh:
        fh.write(f"dead_count={dead_count}\n")


def main() -> int:
    ap = argparse.ArgumentParser(description="Check that every catalog platform URL is alive.")
    ap.add_argument("--readme", default="README.md")
    ap.add_argument("--report", default="liveness-report.md")
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--timeout", type=int, default=25)
    ap.add_argument("--retries", type=int, default=0,
                    help="Extra whole-request retries on top of curl's own --retry (usually 0).")
    ap.add_argument("--min-targets", type=int, default=150,
                    help="Fail (exit 2) if fewer than this many URLs parse — guards against a "
                         "README format change silently emptying the check and false-clearing "
                         "the tracking issue.")
    ap.add_argument("--ci", action="store_true",
                    help="Exit 0 even when dead links are found (report via GITHUB_OUTPUT); "
                         "still exit 2 on an internal error.")
    args = ap.parse_args()

    if shutil.which("curl") is None:
        print("internal error: curl not found on PATH", file=sys.stderr)
        return 2

    try:
        targets = parse_targets(args.readme)
    except Exception as e:  # noqa: BLE001
        print(f"internal error parsing {args.readme}: {e}", file=sys.stderr)
        return 2

    if len(targets) < args.min_targets:
        print(f"internal error: only {len(targets)} platform URLs parsed from {args.readme} "
              f"(floor is {args.min_targets}) — README format likely changed; refusing to run "
              f"so a broken parse can't false-clear the tracking issue.", file=sys.stderr)
        return 2

    platform_cells = sum(len(t["platforms"]) for t in targets)
    print(f"Checking {len(targets)} unique URLs across {platform_cells} platform cells...")

    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(check, t["url"], args.timeout, args.retries): t for t in targets
        }
        for fut in futures:
            t = futures[fut]
            verdict, detail = fut.result()
            results.append({**t, "verdict": verdict, "detail": detail})

    report = build_report(results, len(targets), platform_cells)
    open(args.report, "w", encoding="utf-8").write(report)

    dead = [r for r in results if r["verdict"] == "DEAD"]
    print(f"Done: {len(results) - len(dead)} alive, {len(dead)} dead. Report -> {args.report}")
    for r in sorted(dead, key=lambda x: x["platforms"][0][0].lower()):
        print(f"  DEAD  {r['platforms'][0][0]:32.32}  {r['detail']:26.26}  {r['url']}")

    write_github_output(len(dead))

    if args.ci:
        return 0
    return 1 if dead else 0


if __name__ == "__main__":
    sys.exit(main())
