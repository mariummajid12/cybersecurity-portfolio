import re
import pandas as pd

def extract_iocs(log_file):
    """
    Parses a log file and extracts IPv4 addresses and Hashes.
    """
    # Regex patterns for common IOCs
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    sha256_pattern = r'\b[A-Fa-f0-9]{64}\b'

    with open(log_file, 'r') as f:
        content = f.read()
        
    ips = list(set(re.findall(ip_pattern, content)))
    hashes = list(set(re.findall(sha256_pattern, content)))
    
    return {"ips": ips, "hashes": hashes}

if __name__ == "__main__":
    # Example usage
    found = extract_iocs('../data/sample_logs.txt')
    print(f"Extracted IPs: {found['ips']}")
