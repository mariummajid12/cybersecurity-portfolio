import sys
import os
from scripts.parser import extract_iocs
from scripts.misp_client import create_threat_event

def run_pipeline(log_path):
    print(f"--- Starting Threat Hunt on: {log_path} ---")
    
    # 1. Extract IOCs from logs
    found = extract_iocs(log_path)
    
    if not found['ips'] and not found['hashes']:
        print("No suspicious IOCs found.")
        return

    print(f"Extracted {len(found['ips'])} IPs and {len(found['hashes'])} Hashes.")

    # 2. If IOCs are found, document them in MISP
    event_info = f"Automated Alert: IOCs found in {os.path.basename(log_path)}"
    
    try:
        event_id = create_threat_event("Threat Intelligence Portfolio Test", event_info)
        print(f"--- Pipeline Complete. MISP Event Created: {event_id} ---")
    except Exception as e:
        print(f"Error connecting to MISP: {e}")
        print("Tip: Ensure your .env file is configured and MISP is reachable.")

if __name__ == "__main__":
    # Point this to your sample log file
    sample_log = "data/sample_logs.txt"
    run_pipeline(sample_log)
