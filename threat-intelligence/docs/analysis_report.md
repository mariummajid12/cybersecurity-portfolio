# Incident Analysis Report: Case #2026-04-01-ALPHA

**Status:** Resolved / Documented in MISP  
**Severity:** Medium  
**TLP:** Green  

## 🛡️ Executive Summary
During a routine log audit, a series of suspicious outbound connections were identified originating from a Linux-based development server. Using the `threat-intelligence` toolset, these indicators were extracted, enriched, and correlated against global MISP feeds, identifying a match with a known C2 (Command & Control) infrastructure.

## 🔍 Technical Analysis
1. **Detection:** The `parser.py` script identified a high-frequency connection to `45.33.2.11` on port 80.
2. **Correlation:** Cross-referencing the SHA-256 hash `e3b0c442...` in MISP returned a hit associated with a generic Trojan downloader used in initial access stages.
3. **Log Evidence:**
   - **Source IP:** 192.168.1.50 (Internal Dev)
   - **Destination:** 45.33.2.11 (Known Malicious)
   - **Timestamp:** 2026-04-01 14:05:22

## 🛠️ Remediation Actions
- **Isolation:** The affected host (192.168.1.50) was quarantined at the switch level.
- **Intelligence Update:** A new event was created in the local MISP instance to track this specific variant's behavior across the local subnet.
- **Blocking:** The Destination IP was pushed to the edge firewall blocklist.

## 📈 Tools Used
- **Custom Python Parser** (Regex-based IOC extraction)
- **MISP API (PyMISP)** (Threat enrichment)
- **Pandas** (Data structuring)
