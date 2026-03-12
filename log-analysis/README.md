# Log Analysis: Authentication Threat Detector

A Python tool that parses Linux `auth.log` files to detect suspicious login activity and brute-force indicators.

## Why This Matters

SSH brute-force attacks and credential stuffing are among the most common attack vectors against Linux servers. This tool automates the detection of these patterns from raw authentication logs, the same kind of analysis performed daily in SOC environments.

## What It Detects

| Threat | Description |
|--------|-------------|
| Brute-force attempts | IPs exceeding a configurable failed login threshold |
| Credential stuffing | IPs that failed repeatedly but also achieved a successful login |
| User enumeration | IPs probing for non-existent usernames |

## Files

| File | Description |
|------|-------------|
| `log_parser.py` | Main detection script |
| `sample_auth.log` | Sample log file for testing |

## Usage

```bash
# Run against the sample log
python log_parser.py --log sample_auth.log --threshold 5

# Save report to file
python log_parser.py --log sample_auth.log --threshold 5 --report report.txt

# Generate a fresh sample log
python log_parser.py --sample --log auth.log

# Run against a real system log
python log_parser.py --log /var/log/auth.log --threshold 10
```

## Example Output

```
============================================================
  AUTHENTICATION LOG - THREAT SUMMARY REPORT
  Generated: 2026-03-11 14:33:45
============================================================

[OVERVIEW]
  Total IPs with failed attempts : 3
  Total successful logins        : 2
  IPs with invalid user attempts : 1
  Brute-force threshold          : 5 failed attempts

[SUSPICIOUS IPs - 1 flagged]

  IP: 192.168.1.105
    Failed attempts : 6
    Targeted users  : root
    First seen      : Jan 10 08:01:12
    Last seen       : Jan 10 08:01:27

[HIGH RISK — Successful login after failed attempts]
  ⚠  192.168.1.105 — had 6 failed attempts AND a successful login

[INVALID USER ATTEMPTS]
  203.0.113.45          3 attempts with non-existent usernames
============================================================
```

## Requirements

Python 3.6+ - no external libraries needed (uses standard library only).

## Real-World Application

This type of log analysis is used in:
- **SOC operations** - continuous monitoring for brute-force indicators
- **Incident response** - identifying attacker IPs during post-incident investigation
- **Threat hunting** - proactively searching for compromise indicators in historical logs
