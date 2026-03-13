#!/usr/bin/env python3
"""
Very basic auth log parser.
Summarizes failed SSH logins per username and per source IP.

Usage:
  python auth_log_parser.py --log sample_auth.log
  python auth_log_parser.py --log /var/log/auth.log --top 10
"""

from __future__ import annotations

import argparse
import re
from collections import Counter
from pathlib import Path

# Typical SSH failure lines include either:
# - Failed password for root from 203.0.113.10 port 51432 ssh2
# - Failed password for invalid user admin from 198.51.100.9 port 3333 ssh2
FAILED_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def parse_failed_logins(log_text: str) -> tuple[Counter, Counter, int]:
    """Return (user_counts, ip_counts, total_failed)."""
    user_counts: Counter[str] = Counter()
    ip_counts: Counter[str] = Counter()

    for line in log_text.splitlines():
        match = FAILED_PATTERN.search(line)
        if not match:
            continue

        user = match.group("user")
        ip = match.group("ip")

        user_counts[user] += 1
        ip_counts[ip] += 1

    return user_counts, ip_counts, sum(user_counts.values())


def print_summary(user_counts: Counter, ip_counts: Counter, total: int, top: int) -> None:
    print("=" * 60)
    print("Auth Log Failed Login Summary")
    print("=" * 60)
    print(f"Total failed login attempts: {total}\n")

    print(f"Top {top} targeted users:")
    if user_counts:
        for user, count in user_counts.most_common(top):
            print(f"  - {user}: {count}")
    else:
        print("  - None found")

    print(f"\nTop {top} source IPs:")
    if ip_counts:
        for ip, count in ip_counts.most_common(top):
            print(f"  - {ip}: {count}")
    else:
        print("  - None found")



def main() -> None:
    parser = argparse.ArgumentParser(
        description="Summarize failed SSH login attempts from a Linux auth log."
    )
    parser.add_argument("--log", required=True, help="Path to auth log file")
    parser.add_argument("--top", type=int, default=5, help="How many top entries to show")
    args = parser.parse_args()

    log_path = Path(args.log)
    if not log_path.exists():
        raise SystemExit(f"Log file not found: {log_path}")

    content = log_path.read_text(encoding="utf-8", errors="ignore")
    user_counts, ip_counts, total = parse_failed_logins(content)
    print_summary(user_counts, ip_counts, total, max(args.top, 1))


if __name__ == "__main__":
    main()
