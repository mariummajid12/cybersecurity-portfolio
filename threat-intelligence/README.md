# Threat Intelligence: IOC Analysis & MISP Integration

This repository demonstrates a programmatic approach to **Threat Intelligence (TI)** by correlating forensic log data with known Indicators of Compromise (IOCs) using the **MISP (Malware Information Sharing Platform)**.

## 🎯 Project Objective
To automate the extraction of technical indicators from raw security logs, validate them against global threat feeds, and document attack patterns within a private MISP instance for incident response.

## 🛠 Key Features
- **Automated IOC Extraction:** Python-based parsing of Syslog, Suricata, and Windows Event Logs to identify suspicious IPs, domains, and file hashes (SHA-256).
- **MISP Integration:** Utilizes `PyMISP` to automatically create events, add attributes, and tag sightings based on internal log hits.
- **Correlation Engine:** A custom script that cross-references live network traffic against MISP-stored blacklists to alert on known Command & Control (C2) communication.
- **MITRE ATT&CK Mapping:** All identified threats are tagged with relevant ATT&CK techniques (e.g., T1071 - Application Layer Protocol).

## 🧰 Tech Stack
- **Languages:** Python 3.x
- **Platform:** MISP (Dockerized)
- **Libraries:** PyMISP, Pandas (for log dataframes), Regex
- **Log Sources:** [e.g., Cisco Firepower, Suricata, or Cowrie Honeypot]

## 🚀 How It Works
1. **Ingest:** Raw logs are dropped into the `/data` folder.
2. **Parse:** `parser.py` extracts potential indicators.
3. **Enrich:** The script queries the MISP API to check if the indicator is already known.
4. **Action:** If a match is found, an "Incident Report" is generated in Markdown and a "Sighting" is updated in MISP.

## 📝 Sample Analysis Report
Check the [docs/analysis_report.md](./docs/analysis_report.md) for a deep dive into a simulated **Emotet** infection chain I analyzed using this toolset.
