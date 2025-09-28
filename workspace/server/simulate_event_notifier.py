from event_notifier import app
import json
from unittest.mock import patch

# Simulated device change events (10 devices, realistic changes)
SIMULATED_EVENTS = [
    {
        "event_id": f"evt-{i}",
        "change_id": f"chg-{i}",
        "data": {
            "site": f"DataCenter-{i}",
            "role": (
                "core" if i == 1 else
                "edge" if i == 2 else
                "access" if i == 3 else
                "server" if i == 4 else
                "rack" if i == 5 else
                "generic"
            ),
            "device": f"device{i}",
            "platform": (
                "nxs" if i == 1 else
                "junos" if i == 2 else
                "ios" if i == 3 else
                "hp" if i == 4 else
                "infra" if i == 5 else
                "linux"
            ),
            "vendor": (
                "Cisco" if i in [1, 3] else
                "Juniper" if i == 2 else
                "HP" if i == 4 else
                "APC" if i == 5 else
                "Dell"
            ),
            "details": (
                "BGP ASN changed" if i == 1 else
                "Added ASN and OSPF" if i == 2 else
                "Added VLANs and ACL" if i == 3 else
                "Added RAID disk" if i == 4 else
                "New rack added" if i == 5 else
                "Generic change"
            )
        }
    }
    for i in range(1, 11)
]

def always_true(*args, **kwargs):
    return True

def simulate_events():
    with patch("event_notifier.verify_hmac", always_true):
        with app.test_client() as client:
            for event in SIMULATED_EVENTS:
                response = client.post(
                    "/events/netbox",
                    data=json.dumps(event),
                    content_type="application/json",
                    headers={
                        "X-Event-Id": event["event_id"],
                        "X-Timestamp": "2025-09-17T00:00:00Z",
                        "X-Signature": "fakehmac",
                        "X-Forwarded-For": "10.0.0.1"
                    }
                )
                print(f"Device: {event['data']['device']} | Status: {response.status_code} | Response: {response.data.decode()}")

if __name__ == "__main__":
    simulate_events()