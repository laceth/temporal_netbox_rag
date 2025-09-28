from server.intent_engine import classify_intent, extract_entities, plan_from_intent

def test_classify():
    assert classify_intent("bootstrap new switch") == "netops.device_bootstrap"
    assert classify_intent("change vlan 10") in ("netops.device_config_change","netops.device_bootstrap","general.request")

def test_extract():
    e = extract_entities("MOTD 'AUTHORIZED ACCESS ONLY' vlan 8,10 device sw1 site dc-a 10.2.2.1 mask 255.0.0.0")
    assert e["motd"]
    assert 8 in e.get("vlans_ingress", [])
    assert e["device_name"] == "sw1"

def test_plan():
    out = plan_from_intent({"vlans_ingress":[8,10]})
    assert "cli_preview" in out["artifacts"]
