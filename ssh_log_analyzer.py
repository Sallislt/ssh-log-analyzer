#!/usr/bin/env python3
"""SSH authentication log analyzer.

Reads an OpenSSH auth log (Debian/Ubuntu /var/log/auth.log, RHEL /var/log/secure)
and reports three things a SOC analyst checks first:

  1. brute force: many failed logins from one IP within a short time window;
  2. password spraying: one IP trying many different usernames;
  3. success after failures: an IP that failed several times and then logged in
     (possible compromised account).

Standard library only. Output as readable text or JSON (for a SIEM or a script).

Usage:
    python ssh_log_analyzer.py samples/auth.log
    python ssh_log_analyzer.py /var/log/auth.log --threshold 10 --window 5 --json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from typing import Iterable

# "Oct 23 08:12:03 srv01 sshd[2101]: Failed password for invalid user admin from 203.0.113.45 port 51022 ssh2"
SYSLOG_PREFIX = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}) \S+ sshd\[\d+\]: (?P<msg>.*)$")
# Newer systems may log ISO 8601 timestamps: "2026-10-23T08:12:03.123456+02:00 srv01 sshd[2101]: ..."
ISO_PREFIX = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\S* \S+ sshd\[\d+\]: (?P<msg>.*)$")

FAILED = re.compile(r"^Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")
INVALID = re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>[0-9a-fA-F:.]+)")
ACCEPTED = re.compile(r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")


@dataclass
class Event:
    time: datetime
    kind: str  # "failed" | "accepted"
    user: str
    ip: str
    method: str = ""


@dataclass
class Finding:
    severity: str  # "high" | "medium"
    rule: str
    ip: str
    detail: str
    first_seen: str
    last_seen: str
    users: list[str] = field(default_factory=list)


def parse_line(line: str, year: int) -> Event | None:
    """Turns one log line into an Event, or None if it is not relevant."""
    m = SYSLOG_PREFIX.match(line) or ISO_PREFIX.match(line)
    if not m:
        return None

    ts = m.group("ts")
    try:
        if "T" in ts:
            when = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S")
        else:
            # classic syslog lines have no year
            when = datetime.strptime(f"{year} {' '.join(ts.split())}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None

    msg = m.group("msg")
    if f := FAILED.match(msg):
        return Event(when, "failed", f["user"], f["ip"])
    if a := ACCEPTED.match(msg):
        return Event(when, "accepted", a["user"], a["ip"], a["method"])
    # "Invalid user" is always followed by a "Failed ..." line for the same
    # attempt, so it is ignored here to avoid counting the attempt twice.
    return None


def parse(lines: Iterable[str], year: int) -> list[Event]:
    return [e for e in (parse_line(l.rstrip("\n"), year) for l in lines) if e]


def max_in_window(times: list[datetime], window: timedelta) -> tuple[int, datetime, datetime]:
    """Largest number of events inside any sliding window (two pointers)."""
    times = sorted(times)
    best, best_start, best_end = 0, times[0], times[0]
    start = 0
    for end, t in enumerate(times):
        while t - times[start] > window:
            start += 1
        if end - start + 1 > best:
            best, best_start, best_end = end - start + 1, times[start], t
    return best, best_start, best_end


def analyze(events: list[Event], threshold: int, window_minutes: int, spray_users: int) -> list[Finding]:
    window = timedelta(minutes=window_minutes)
    failed_by_ip: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.kind == "failed":
            failed_by_ip[e.ip].append(e)

    findings: list[Finding] = []
    fmt = "%Y-%m-%d %H:%M:%S"

    for ip, fails in failed_by_ip.items():
        users = sorted({f.user for f in fails})

        count, start, end = max_in_window([f.time for f in fails], window)
        if count >= threshold:
            findings.append(Finding(
                "high", "brute_force", ip,
                f"{count} failed logins within {window_minutes} min",
                start.strftime(fmt), end.strftime(fmt), users,
            ))

        if len(users) >= spray_users:
            findings.append(Finding(
                "medium", "password_spraying", ip,
                f"{len(users)} different usernames tried",
                min(f.time for f in fails).strftime(fmt), max(f.time for f in fails).strftime(fmt), users,
            ))

    # success after failures, from the same IP
    for e in events:
        if e.kind != "accepted":
            continue
        previous = [f for f in failed_by_ip.get(e.ip, []) if f.time <= e.time]
        if len(previous) >= 3:
            findings.append(Finding(
                "high", "success_after_failures", e.ip,
                f"login as '{e.user}' ({e.method}) after {len(previous)} failures",
                previous[0].time.strftime(fmt), e.time.strftime(fmt), [e.user],
            ))

    order = {"high": 0, "medium": 1}
    return sorted(findings, key=lambda f: (order[f.severity], f.first_seen))


def summary(events: list[Event]) -> dict:
    failed = [e for e in events if e.kind == "failed"]
    accepted = [e for e in events if e.kind == "accepted"]
    top_ips: dict[str, int] = defaultdict(int)
    for e in failed:
        top_ips[e.ip] += 1
    return {
        "failed": len(failed),
        "accepted": len(accepted),
        "unique_source_ips": len({e.ip for e in failed}),
        "top_failed_ips": sorted(top_ips.items(), key=lambda kv: kv[1], reverse=True)[:5],
    }


def render_text(stats: dict, findings: list[Finding]) -> str:
    out = [
        "SSH log analysis",
        "================",
        f"Failed logins     : {stats['failed']}",
        f"Successful logins : {stats['accepted']}",
        f"Unique source IPs : {stats['unique_source_ips']}",
        "",
        "Top failed source IPs:",
    ]
    out += [f"  {count:>5}  {ip}" for ip, count in stats["top_failed_ips"]] or ["  none"]
    out += ["", f"Findings ({len(findings)}):"]
    if not findings:
        out.append("  nothing suspicious")
    for f in findings:
        out.append(f"  [{f.severity.upper():<6}] {f.rule:<23} {f.ip:<16} {f.detail}")
        out.append(f"           {f.first_seen} -> {f.last_seen}  users: {', '.join(f.users)}")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Detect brute force and suspicious logins in an SSH auth log.")
    p.add_argument("logfile", help="auth log file, or '-' for standard input")
    p.add_argument("--threshold", type=int, default=5, help="failures from one IP to flag brute force (default 5)")
    p.add_argument("--window", type=int, default=10, help="time window in minutes (default 10)")
    p.add_argument("--spray-users", type=int, default=3, help="distinct usernames from one IP to flag spraying (default 3)")
    p.add_argument("--year", type=int, default=datetime.now().year, help="year for syslog lines without one")
    p.add_argument("--json", action="store_true", help="JSON output")
    args = p.parse_args(argv)

    if args.logfile == "-":
        events = parse(sys.stdin, args.year)
    else:
        with open(args.logfile, encoding="utf-8", errors="replace") as fh:
            events = parse(fh, args.year)

    findings = analyze(events, args.threshold, args.window, args.spray_users)
    stats = summary(events)

    if args.json:
        print(json.dumps({"summary": stats, "findings": [asdict(f) for f in findings]}, indent=2))
    else:
        print(render_text(stats, findings))

    # non-zero exit code when something high severity was found (handy in scripts)
    return 2 if any(f.severity == "high" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
