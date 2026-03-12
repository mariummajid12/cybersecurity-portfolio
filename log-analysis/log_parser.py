"""
log_parser.py
-------------
Parses Linux auth.log files to detect suspicious login activity.
Identifies brute-force indicators by flagging IPs with repeated
failed authentication attempts above a configurable threshold.

Usage:
    python log_parser.py --log auth.log --threshold 5 --report report.txt

Author: Marium Majid
Course/Project: Network Security Portfolio
"""

import re
import argparse
from collections import defaultdict
from datetime import datetime


# ── Regex patterns ────────────────────────────────────────────────────────────
FAILED_LOGIN_PATTERN = re.compile(
    r"(\w+\s+\d+\s+\d+:\d+:\d+).*Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
)
ACCEPTED_LOGIN_PATTERN = re.compile(
    r"(\w+\s+\d+\s+\d+:\d+:\d+).*Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)"
)
INVALID_USER_PATTERN = re.compile(
    r"(\w+\s+\d+\s+\d+:\d+:\d+).*Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)"
)


def parse_log(filepath):
    """Parse auth.log and extract login events."""
    failed_attempts = defaultdict(list)   # ip -> list of (timestamp, username)
    accepted_logins = []
    invalid_users = defaultdict(int)      # ip -> count

    try:
        with open(filepath, "r") as f:
            for line in f:
                # Failed password attempts
                match = FAILED_LOGIN_PATTERN.search(line)
                if match:
                    timestamp, username, ip = match.groups()
                    failed_attempts[ip].append((timestamp, username))
                    continue

                # Successful logins
                match = ACCEPTED_LOGIN_PATTERN.search(line)
                if match:
                    timestamp, username, ip = match.groups()
                    accepted_logins.append((timestamp, username, ip))
                    continue

                # Invalid user attempts
                match = INVALID_USER_PATTERN.search(line)
                if match:
                    timestamp, username, ip = match.groups()
                    invalid_users[ip] += 1

    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {filepath}")
        exit(1)

    return failed_attempts, accepted_logins, invalid_users


def analyse(failed_attempts, accepted_logins, invalid_users, threshold):
    """Identify suspicious IPs based on failed attempt threshold."""
    suspicious_ips = {
        ip: attempts
        for ip, attempts in failed_attempts.items()
        if len(attempts) >= threshold
    }

    # Flag IPs that failed many times but also had a successful login (possible credential stuffing)
    successful_ips = {ip for _, _, ip in accepted_logins}
    compromise_risk = [ip for ip in suspicious_ips if ip in successful_ips]

    return suspicious_ips, compromise_risk


def generate_report(failed_attempts, accepted_logins, invalid_users,
                    suspicious_ips, compromise_risk, threshold, output_path=None):
    """Generate a human-readable threat summary report."""
    lines = []
    lines.append("=" * 60)
    lines.append("  AUTHENTICATION LOG — THREAT SUMMARY REPORT")
    lines.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 60)

    lines.append(f"\n[OVERVIEW]")
    lines.append(f"  Total IPs with failed attempts : {len(failed_attempts)}")
    lines.append(f"  Total successful logins        : {len(accepted_logins)}")
    lines.append(f"  IPs with invalid user attempts : {len(invalid_users)}")
    lines.append(f"  Brute-force threshold          : {threshold} failed attempts")

    lines.append(f"\n[SUSPICIOUS IPs — {len(suspicious_ips)} flagged]")
    if suspicious_ips:
        for ip, attempts in sorted(suspicious_ips.items(), key=lambda x: -len(x[1])):
            usernames = list(set(u for _, u in attempts))
            lines.append(f"\n  IP: {ip}")
            lines.append(f"    Failed attempts : {len(attempts)}")
            lines.append(f"    Targeted users  : {', '.join(usernames)}")
            lines.append(f"    First seen      : {attempts[0][0]}")
            lines.append(f"    Last seen       : {attempts[-1][0]}")
    else:
        lines.append("  None detected above threshold.")

    lines.append(f"\n[HIGH RISK — Successful login after failed attempts]")
    if compromise_risk:
        for ip in compromise_risk:
            lines.append(f"  ⚠  {ip} — had {len(suspicious_ips[ip])} failed attempts AND a successful login")
    else:
        lines.append("  None detected.")

    lines.append(f"\n[INVALID USER ATTEMPTS]")
    if invalid_users:
        for ip, count in sorted(invalid_users.items(), key=lambda x: -x[1])[:10]:
            lines.append(f"  {ip:20s}  {count} attempts with non-existent usernames")
    else:
        lines.append("  None detected.")

    lines.append(f"\n[SUCCESSFUL LOGINS]")
    if accepted_logins:
        for ts, user, ip in accepted_logins[:10]:
            lines.append(f"  {ts}  user={user}  from={ip}")
        if len(accepted_logins) > 10:
            lines.append(f"  ... and {len(accepted_logins) - 10} more")
    else:
        lines.append("  None recorded.")

    lines.append("\n" + "=" * 60)
    report = "\n".join(lines)

    print(report)

    if output_path:
        with open(output_path, "w") as f:
            f.write(report)
        print(f"\n[INFO] Report saved to: {output_path}")


def generate_sample_log(filepath):
    """Generate a sample auth.log for testing."""
    sample = """Jan 10 08:01:12 server sshd[1234]: Failed password for root from 192.168.1.105 port 22 ssh2
Jan 10 08:01:15 server sshd[1234]: Failed password for root from 192.168.1.105 port 22 ssh2
Jan 10 08:01:18 server sshd[1234]: Failed password for root from 192.168.1.105 port 22 ssh2
Jan 10 08:01:21 server sshd[1234]: Failed password for root from 192.168.1.105 port 22 ssh2
Jan 10 08:01:24 server sshd[1234]: Failed password for root from 192.168.1.105 port 22 ssh2
Jan 10 08:01:27 server sshd[1234]: Failed password for root from 192.168.1.105 port 22 ssh2
Jan 10 08:05:00 server sshd[1235]: Accepted password for admin from 192.168.1.105 port 22 ssh2
Jan 10 09:10:00 server sshd[1236]: Failed password for invalid user guest from 10.0.0.22 port 22 ssh2
Jan 10 09:10:03 server sshd[1236]: Failed password for invalid user guest from 10.0.0.22 port 22 ssh2
Jan 10 09:10:06 server sshd[1236]: Failed password for invalid user test from 10.0.0.22 port 22 ssh2
Jan 10 10:00:00 server sshd[1237]: Accepted password for marium from 10.0.0.50 port 22 ssh2
Jan 10 10:15:00 server sshd[1238]: Invalid user oracle from 203.0.113.45
Jan 10 10:15:01 server sshd[1238]: Invalid user postgres from 203.0.113.45
Jan 10 10:15:02 server sshd[1238]: Invalid user ubuntu from 203.0.113.45
Jan 10 11:00:00 server sshd[1239]: Failed password for root from 198.51.100.7 port 22 ssh2
Jan 10 11:00:03 server sshd[1239]: Failed password for root from 198.51.100.7 port 22 ssh2
"""
    with open(filepath, "w") as f:
        f.write(sample)
    print(f"[INFO] Sample log generated: {filepath}")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Parse auth.log and detect suspicious login activity."
    )
    parser.add_argument("--log", default="auth.log", help="Path to auth.log file")
    parser.add_argument("--threshold", type=int, default=5,
                        help="Failed attempt threshold to flag an IP (default: 5)")
    parser.add_argument("--report", default=None, help="Optional path to save report")
    parser.add_argument("--sample", action="store_true",
                        help="Generate a sample auth.log for testing")
    args = parser.parse_args()

    if args.sample:
        generate_sample_log(args.log)

    failed_attempts, accepted_logins, invalid_users = parse_log(args.log)
    suspicious_ips, compromise_risk = analyse(
        failed_attempts, accepted_logins, invalid_users, args.threshold
    )
    generate_report(
        failed_attempts, accepted_logins, invalid_users,
        suspicious_ips, compromise_risk, args.threshold, args.report
    )


if __name__ == "__main__":
    main()
