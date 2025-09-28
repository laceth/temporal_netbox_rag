import sys
from unittest.mock import patch
import netbox_export



FAKE_OBJECT_CHANGES = {
    "results": [
        # Cisco NXS: BGP ASN change
        {"action": 2, "changed_object_type": {"model": "device"}, "changed_object_id": 1},
        # Juniper MX80: Add ASN, OSPF
        {"action": 2, "changed_object_type": {"model": "device"}, "changed_object_id": 2},
        # Cisco 2926: Add VLANs, ACL
        {"action": 2, "changed_object_type": {"model": "device"}, "changed_object_id": 3},
        # HP 360D: Add RAID disk
        {"action": 2, "changed_object_type": {"model": "device"}, "changed_object_id": 4},
        # Rack 303: Add new rack
        {"action": 2, "changed_object_type": {"model": "rack"}, "changed_object_id": 5},
        # Add more generic device changes
        *[
            {"action": 2, "changed_object_type": {"model": "device"}, "changed_object_id": i}
            for i in range(6, 11)
        ]
    ],
    "next": None
}

FAKE_DEVICES = [
    {
        "id": 1,
        "name": "nxs01",
        "site": {"slug": "dc1", "name": "DataCenter-1"},
        "device_role": {"slug": "core", "name": "Core"},
        "platform": {"slug": "nxs"},
        "device_type": {"manufacturer": {"name": "Cisco"}, "model": "Nexus 9000"},
        "primary_ip4": {"address": "10.1.1.1/32"},
        "primary_ip6": None,
        "bgp_asn": 65001,
        "change_details": "BGP ASN changed from 65000 to 65001",
    },
    {
        "id": 2,
        "name": "mx80-1",
        "site": {"slug": "dc2", "name": "DataCenter-2"},
        "device_role": {"slug": "edge", "name": "Edge"},
        "platform": {"slug": "junos"},
        "device_type": {"manufacturer": {"name": "Juniper"}, "model": "MX80"},
        "primary_ip4": {"address": "10.2.2.2/32"},
        "primary_ip6": None,
        "bgp_asn": 65100,
        "ospf_area": "0.0.0.1",
        "change_details": "Added ASN 65100 and OSPF area 0.0.0.1",
    },
    {
        "id": 3,
        "name": "sw2926-1",
        "site": {"slug": "dc3", "name": "DataCenter-3"},
        "device_role": {"slug": "access", "name": "Access"},
        "platform": {"slug": "ios"},
        "device_type": {"manufacturer": {"name": "Cisco"}, "model": "Catalyst 2926"},
        "primary_ip4": {"address": "10.3.3.3/32"},
        "primary_ip6": None,
        "vlans": [
            {"id": 301, "vid": 10, "name": "Ingress"},
            {"id": 302, "vid": 20, "name": "Voice"},
            {"id": 303, "vid": 30, "name": "Mgmt"},
        ],
        "acls": ["deny ip any any"],
        "change_details": "Added 3 VLANs and ACL deny ip any any",
    },
    {
        "id": 4,
        "name": "hp360d-1",
        "site": {"slug": "dc4", "name": "DataCenter-4"},
        "device_role": {"slug": "server", "name": "Server"},
        "platform": {"slug": "hp"},
        "device_type": {"manufacturer": {"name": "HP"}, "model": "ProLiant 360D"},
        "primary_ip4": {"address": "10.4.4.4/32"},
        "primary_ip6": None,
        "raid": "RAID5",
        "disks": ["2TB", "2TB", "2TB", "2TB"],
        "change_details": "Added new 2TB disk, set RAID5",
    },
    {
        "id": 5,
        "name": "rack303",
        "site": {"slug": "dc5", "name": "DataCenter-5"},
        "device_role": {"slug": "rack", "name": "Rack"},
        "platform": {"slug": "infra"},
        "device_type": {"manufacturer": {"name": "APC"}, "model": "Rack 303"},
        "primary_ip4": None,
        "primary_ip6": None,
        "rack_details": "Added new rack with wire distro panels, shelf, row",
        "change_details": "New rack added with wire distro panels, shelf, row",
    },
    # Add 5 more generic devices
    *[
        {
            "id": i,
            "name": f"device{i}",
            "site": {"slug": f"dc{i}", "name": f"DataCenter-{i}"},
            "device_role": {"slug": "generic", "name": "Generic"},
            "platform": {"slug": "linux"},
            "device_type": {"manufacturer": {"name": "Dell"}, "model": "PowerEdge"},
            "primary_ip4": {"address": f"10.{i}.{i}.{i}/32"},
            "primary_ip6": None,
            "change_details": f"Generic change for device{i}",
        }
        for i in range(6, 11)
    ]
]

def fake_get_json(sess, url, params=None, verify=True):
    if "object-changes" in url:
        return FAKE_OBJECT_CHANGES
    if "devices" in url:
        return {"results": FAKE_DEVICES, "next": None}
    return {}

# In your printout, add:
for d in FAKE_DEVICES:
    ds = netbox_export.device_summary(d)
    print("- %(name)s site=%(site)s role=%(role)s mgmt=%(mgmt_ip)s platform=%(platform)s vendor=%(vendor)s" % ds)
    if "change_details" in d:
        print(f"    Change: {d['change_details']}")
    if "vlans" in d:
        for vlan in d["vlans"]:
            print(f"    VLAN: {vlan['vid']} ({vlan['name']})")
    if "acls" in d:
        for acl in d["acls"]:
            print(f"    ACL: {acl}")
    if "raid" in d:
        print(f"    RAID: {d['raid']} Disks: {', '.join(d['disks'])}")
    if "rack_details" in d:
        print(f"    Rack Details: {d['rack_details']}")

def main_sim():
    with patch("netbox_export.get_json", side_effect=fake_get_json):
        sys.argv = [
            "netbox_export.py",
            "--since", "24h",
            "--types", "device", "interface", "vlan",
            "--dry-run"
        ]
        # Run and capture output
        devices = None
        try:
            netbox_export.main()
        except SystemExit:
            pass
        # Print extra details for demo
        print("\nDetailed device info:")
        for d in FAKE_DEVICES:
            ds = netbox_export.device_summary(d)
            print("- %(name)s site=%(site)s role=%(role)s mgmt=%(mgmt_ip)s platform=%(platform)s vendor=%(vendor)s" % ds)
            if "interfaces" in d:
                for iface in d["interfaces"]:
                    print(f"    Interface: {iface['name']} IP: {iface['ip']}")
            if "vlans" in d:
                for vlan in d["vlans"]:
                    print(f"    VLAN: {vlan['vid']} ({vlan['name']})")

if __name__ == "__main__":
    main_sim()
