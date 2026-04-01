import os
from pymisp import PyMISP, MISPEvent
from dotenv import load_dotenv

# Load API keys from a .env file (Never hardcode keys on GitHub!)
load_dotenv()

MISP_URL = os.getenv('MISP_URL')
MISP_KEY = os.getenv('MISP_KEY')
MISP_VERIFYCERT = False

def init_misp():
    return PyMISP(MISP_URL, MISP_KEY, MISP_VERIFYCERT)

def create_threat_event(summary, info, threat_level=3):
    """
    Creates a new event in MISP for a detected threat.
    Threat Levels: 1=High, 2=Medium, 3=Low, 4=Undefined
    """
    misp = init_misp()
    event = MISPEvent()
    event.info = info
    event.threat_level_id = threat_level
    event.analysis = 0 # 0 = Initial
    
    # Add the event to MISP
    created_event = misp.add_event(event)
    print(f"Successfully created MISP Event ID: {created_event['Event']['id']}")
    return created_event['Event']['id']

if __name__ == "__main__":
    # Quick test execution
    create_threat_event("Suspicious Network Activity", "Potential C2 Traffic detected in Perimeter Firewall")
