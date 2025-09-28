import re, ipaddress, os
from typing import Dict, Any, List, Optional, Tuple
from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from .tools.netbox_api import NetBoxClient

VENDOR_MAP = {
    "cisco": "cisco_ios",
    "cisco systems": "cisco_ios",
    "arista": "arista_eos",
    "juniper": "juniper_junos",
}

def classify_intent(text: str) -> str:
    t = text.lower()
    if any(k in t for k in ["bootstrap","standup","instantiate","bring up","zero touch","ztp"]):
        return "netops.device_bootstrap"
    if any(k in t for k in ["vlan","motd","interface","svi"]):
        return "netops.device_config_change"
    return "general.request"

_vlan_token = r"(?:\d{1,4}|\d{1,4}\s*-\s*\d{1,4})"
_vlan_list = rf"{_vlan_token}(?:\s*,\s*{_vlan_token})*"

def _parse_vlans(s: str) -> List[int]:
    vals: List[int] = []
    for part in re.split(r"[\s,]+", s.strip()):
        if not part: continue
        if "-" in part:
            a,b = part.split("-",1)
            try:
                a=int(a); b=int(b)
                vals.extend(range(min(a,b), max(a,b)+1))
            except: pass
        else:
            try: vals.append(int(part))
            except: pass
    return sorted({v for v in vals if 1 <= v <= 4094})

def _findall(pattern: str, text: str, flags=0) -> List[str]:
    return [m.group(1) for m in re.finditer(pattern, text, flags)]

def extract_entities(text: str) -> Dict[str, Any]:
    """Extract common NetOps entities from free text (simple rule-based)."""
    entities: Dict[str, Any] = {}
    # MOTD
    m = re.search(r"motd\s+(?:"([^"]+)"|'([^']+)'|\^([^\^]+)\^|([^\n]+))", text, re.I)
    if m:
        entities["motd"] = next((g for g in m.groups() if g), None)

    # VLAN ingress mention
    m = re.search(r"vlan[s]?\s+((?:%s)(?:\s*,\s*(?:%s))*)" % (_vlan_token, _vlan_token), text, re.I)
    if m:
        entities["vlans_ingress"] = _parse_vlans(m.group(1))

    # Specific interface -> vlan mappings (simple)
    maps = []
    for iface, vlan in re.findall(r"(Gi\S+|ge-\S+|xe-\S+|Ethernet\S+)\s*(?:to|=|:)\s*vlan\s*(\d{1,4})", text, re.I):
        try:
            maps.append({"interface": iface, "vlan": int(vlan)})
        except: pass
    if maps:
        entities["interface_vlan_map"] = maps

    # mgmt ip + mask
    ipm = re.search(r"(\d+\.\d+\.\d+\.\d+)\s*(?:mask|/)?\s*(\d+\.\d+\.\d+\.\d+|\d{1,2})", text)
    if ipm:
        ip, mask = ipm.group(1), ipm.group(2)
        if mask.isdigit():
            try:
                mask = str(ipaddress.IPv4Network(f"0.0.0.0/{mask}", strict=False).netmask)
            except: pass
        entities["mgmt_ip"] = ip
        entities["mgmt_mask"] = mask

    # device name, site hints
    dn = re.search(r"device\s+([\w-]+)", text, re.I)
    if dn: entities["device_name"] = dn.group(1)
    st = re.search(r"site\s+([\w-]+)", text, re.I)
    if st: entities["site"] = st.group(1)

    return entities

def _vendor_from_netbox(netbox: NetBoxClient, device_name: Optional[str]) -> Optional[str]:
    if not (netbox and device_name): return None
    mfg = netbox.get_device_vendor(device_name)
    if not mfg: return None
    for key, templ in VENDOR_MAP.items():
        if key in mfg:
            return templ
    return None

def _env() -> Environment:
    root = os.path.join(os.path.dirname(__file__), "vendor_templates")
    env = Environment(
        loader=FileSystemLoader(root),
        autoescape=select_autoescape(disabled_extensions=("j2",)),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    return env

def plan_from_intent(entities: Dict[str, Any], device_name: Optional[str]=None) -> Dict[str, Any]:
    """Compose a vendor-agnostic plan, and render CLI from a Jinja template."""
    netbox = NetBoxClient()
    # vendor selection
    vendor_template = entities.get("vendor_template")
    if not vendor_template:
        vendor_template = _vendor_from_netbox(netbox, device_name) or "cisco_ios"

    # defaults
    motd = entities.get("motd", "AUTHORIZED ACCESS ONLY")
    vlans_ingress = entities.get("vlans_ingress", [8,10])
    vlans_egress = entities.get("vlans_egress", "all")
    ingress_interfaces = entities.get("ingress_interfaces", ["Gi1/0/1-24"])
    uplink_trunks = entities.get("uplink_trunks", ["Gi1/0/49-50"])
    mgmt_interface = entities.get("mgmt_interface", "Vlan1")
    mgmt_ip = entities.get("mgmt_ip", "10.2.2.1")
    mgmt_mask = entities.get("mgmt_mask", "255.0.0.0")

    env = _env()
    template = env.get_template(f"{vendor_template}.j2")
    cli = template.render(
        motd=motd,
        vlans_ingress=vlans_ingress,
        vlans_egress=vlans_egress,
        ingress_interfaces=ingress_interfaces,
        uplink_trunks=uplink_trunks,
        mgmt_interface=mgmt_interface,
        mgmt_ip=mgmt_ip,
        mgmt_mask=mgmt_mask,
    )

    return {
        "intent": "netops.device_bootstrap",
        "vendor_template": vendor_template,
        "entities": {
            "motd": motd,
            "vlans_ingress": vlans_ingress,
            "vlans_egress": vlans_egress,
            "ingress_interfaces": ingress_interfaces,
            "uplink_trunks": uplink_trunks,
            "mgmt_interface": mgmt_interface,
            "mgmt_ip": mgmt_ip,
            "mgmt_mask": mgmt_mask,
            "device_name": device_name,
        },
        "artifacts": {
            "cli_preview": cli.strip() + "\n"
        }
    }
