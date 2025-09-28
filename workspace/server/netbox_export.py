#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netbox_export.py
----------------
Extract NetBox inventory *changes* (extras/object-changes), resolve to devices,
and export filtered device data to:
  1) Ansible inventory YAML (group by site and role)
  2) Terraform variables (devices.auto.tfvars.json) or HCL locals

Requires: requests, pyyaml (for YAML export), python-dateutil (for 'since' parsing)

Env:
  NETBOX_URL      = https://netbox.example.com
  NETBOX_TOKEN    = <api token>
  NETBOX_VERIFY_SSL = 1|0 (default 1)

Usage examples:
  # changes in last 24h, devices only, export both formats
  python3 netbox_export.py --since 24h --types device --ansible-out inv.yaml --tfvars-out devices.auto.tfvars.json

  # changes since timestamp, site filter, and HCL locals
  python3 netbox_export.py --since 2025-09-01T00:00:00Z --site PA-1 --hcl-out locals.devices.tf

  # just print which devices changed (dry-run)
  python3 netbox_export.py --since 48h --types device interface --dry-run

Notes:
- NetBox ObjectChange actions: 1=create, 2=update, 3=delete. We ignore deletes for exports.
- For interface/IP changes, we resolve the parent device so you can export device-level info.
- If an object has no device (e.g., site), it won't be in the device export unless --include-nondevices is used.
"""
import os, sys, json, time, argparse, re
import requests
from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin, urlencode
try:
    import yaml
except Exception:
    yaml = None

try:
    from dateutil import parser as dtparser
except Exception:
    dtparser = None

# -------------------------------
# Helpers
# -------------------------------
def env_bool(name, default=True):
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in ("1","true","yes","y")

def parse_since(s):
    """
    Accepts:
      - '24h', '7d', '30m' relative durations
      - ISO8601 '2025-09-01T00:00:00Z' or '2025-09-01 00:00:00'
    Returns UTC ISO8601 string for created__gte.
    """
    if not s:
        return None
    m = re.match(r"^(\d+)\s*([smhdw])$", s.strip(), re.I)
    if m:
        qty = int(m.group(1))
        unit = m.group(2).lower()
        mult = {'s':1, 'm':60, 'h':3600, 'd':86400, 'w':604800}[unit]
        ts = datetime.now(timezone.utc) - timedelta(seconds=qty*mult)
        return ts.isoformat()
    # ISO parse
    if dtparser:
        dt = dtparser.parse(s)
        if not dt.tzinfo:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt.isoformat()
    # Fallback: pass through
    return s

def headers(token):
    return {"Authorization": "Token %s" % token, "Accept": "application/json"}

def get_json(sess, url, params=None, verify=True):
    try:
        r = sess.get(url, params=params or {}, timeout=15, verify=verify)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.RequestException as e:
        print(f"Network error fetching {url}: {e}", file=sys.stderr)
        raise
    except ValueError as e:
        print(f"Invalid JSON from {url}: {e}", file=sys.stderr)
        raise

def paged(sess, base_url, params, verify=True):
    url = base_url
    while True:
        try:
            data = get_json(sess, url, params=params, verify=verify)
        except Exception:
            # propagate to caller after logging
            raise
        for item in data.get("results", []):
            yield item
        next_url = data.get("next")
        if not next_url:
            break
        url = next_url
        params = None  # 'next' already has the query

def netbox_get(sess, base, path, params=None, verify=True):
    try:
        return get_json(sess, urljoin(base, path), params=params, verify=verify)
    except Exception:
        raise

# -------------------------------
# API wrappers
# -------------------------------
def fetch_object_changes(sess, base, token, since=None, types=None, site=None, role=None, tenant=None, tag=None, limit=1000, verify=True):
    """
    Fetch ObjectChange records since 'since' timestamp; filter by content type list (e.g., ['device','interface']).
    Returns a list of dicts.
    """
    params = {"limit": 200, "ordering": "-time"}  # newest first
    if since:
        params["time__gte"] = since if "T" in since else since  # NetBox 3.6+: 'time__gte' (older: 'created__gte')
        # fall back to created__gte for compatibility
        params["created__gte"] = since
    # We will post-filter 'types' because content-type filtering varies
    url = urljoin(base, "/api/extras/object-changes/")
    out = []
    try:
        for oc in paged(sess, url, params, verify=verify):
            ct = oc.get("changed_object_type") or {}
            model = ct.get("model") or ""  # e.g., "device", "interface"
            if types and model not in types:
                continue
            out.append(oc)
            if limit and len(out) >= limit:
                break
    except Exception:
        print(f"Error fetching object changes from {url}", file=sys.stderr)
        raise
    return out

def resolve_changed_devices(sess, base, token, changes, verify=True):
    """
    From ObjectChange records, deduce device IDs that are impacted.
    For device changes: take changed_object_id (unless action=delete).
    For interface/IP/etc: fetch to identify parent device.
    """
    device_ids = set()
    for oc in changes:
        action = oc.get("action")
        if action == 3:  # delete
            continue
        ct = (oc.get("changed_object_type") or {})
        model = (ct.get("model") or "").lower()
        obj_id = oc.get("changed_object_id")
        if model == "device":
            device_ids.add(obj_id)
            continue
        # try to map back to device for other models
        if model == "interface":
            try:
                iface = netbox_get(sess, base, "/api/dcim/interfaces/%s/" % obj_id, verify=verify)
                if iface.get("device") and iface["device"].get("id"):
                    device_ids.add(iface["device"]["id"])
            except Exception as e:
                print(f"Warning: could not resolve interface {obj_id}: {e}", file=sys.stderr)
        elif model in ("ip-address","ipaddress"):
            try:
                ip = netbox_get(sess, base, "/api/ipam/ip-addresses/%s/" % obj_id, verify=verify)
                # ip may have assigned_object with device via interface
                assigned = ip.get("assigned_object") or {}
                dev = assigned.get("device") or (assigned.get("interface", {}) or {}).get("device") or {}
                if dev.get("id"):
                    device_ids.add(dev["id"])
            except Exception as e:
                print(f"Warning: could not resolve ip-address {obj_id}: {e}", file=sys.stderr)
        # extend for vlan, prefix, etc. as needed
    return sorted(device_ids)

def fetch_devices(sess, base, token, device_ids=None, site=None, role=None, tenant=None, tag=None, verify=True):
    """
    Pull devices with selected fields; can filter by ids or by site/role/tenant/tag.
    """
    params = {"limit": 200}
    if site:
        params["site"] = site
    if role:
        params["role"] = role
    if tenant:
        params["tenant"] = tenant
    if tag:
        params["tag"] = tag

    url = urljoin(base, "/api/dcim/devices/")
    results = []
    try:
        for d in paged(sess, url, params, verify=verify):
            if device_ids and d.get("id") not in device_ids:
                continue
            results.append(d)
    except Exception as e:
        print(f"Error fetching devices: {e}", file=sys.stderr)
        raise
    return results

def device_summary(d):
    name = d.get("name")
    site = (d.get("site") or {}).get("slug") or (d.get("site") or {}).get("name")
    role = (d.get("device_role") or {}).get("slug") or (d.get("device_role") or {}).get("name")
    plat = (d.get("platform") or {}).get("slug") or ""
    vendor = (d.get("device_type") or {}).get("manufacturer", {}).get("name") or ""
    dtype = (d.get("device_type") or {}).get("model") or ""
    # mgmt ip
    pip4 = (d.get("primary_ip4") or {}).get("address") or ""
    pip6 = (d.get("primary_ip6") or {}).get("address") or ""
    mgmt = pip4 or pip6
    if "/" in mgmt:
        mgmt = mgmt.split("/")[0]
    return {
        "id": d.get("id"),
        "name": name,
        "site": site,
        "role": role,
        "platform": plat,
        "vendor": vendor,
        "device_type": dtype,
        "mgmt_ip": mgmt
    }

def infer_ansible_network_os(platform_slug, vendor_name):
    # very simple heuristic; adjust to your naming
    if platform_slug:
        if "nxos" in platform_slug: return "cisco.nxos.nxos"
        if "iosxr" in platform_slug: return "cisco.iosxr.iosxr"
        if "ios" in platform_slug: return "cisco.ios.ios"
        if "eos" in platform_slug: return "arista.eos.eos"
        if "junos" in platform_slug or "juniper" in platform_slug: return "junipernetworks.junos.junos"
    v = (vendor_name or "").lower()
    if "arista" in v: return "arista.eos.eos"
    if "juniper" in v: return "junipernetworks.junos.junos"
    if "cisco" in v: return "cisco.ios.ios"
    return None

# -------------------------------
# Exports
# -------------------------------
def export_ansible(devices, out_path):
    if yaml is None:
        raise SystemExit("PyYAML not installed. Run: pip install pyyaml")
    # Build groups by site and role; put hosts under 'all'
    inv = {"all": {"hosts": {}, "children": {}}}
    for d in devices:
        ds = device_summary(d)
        hostvars = {
            "ansible_host": ds["mgmt_ip"],
            "site": ds["site"],
            "role": ds["role"],
            "platform": ds["platform"],
            "vendor": ds["vendor"],
            "device_type": ds["device_type"],
        }
        anet = infer_ansible_network_os(ds["platform"], ds["vendor"])
        if anet:
            hostvars["ansible_network_os"] = anet
        inv["all"]["hosts"][ds["name"]] = hostvars

        # site group
        sgrp = ds["site"] or "unknown_site"
        inv["all"]["children"].setdefault(sgrp, {"hosts": {}, "children": {}})
        inv["all"]["children"][sgrp]["hosts"][ds["name"]] = {}

        # role group under site
        rgrp = ds["role"] or "unknown_role"
        inv["all"]["children"][sgrp]["children"].setdefault(rgrp, {"hosts": {}})
        inv["all"]["children"][sgrp]["children"][rgrp]["hosts"][ds["name"]] = {}

    try:
        with open(out_path, "w") as f:
            yaml.safe_dump(inv, f, sort_keys=False)
        return out_path
    except Exception as e:
        print(f"Error writing Ansible inventory to {out_path}: {e}", file=sys.stderr)
        raise

def export_tfvars(devices, out_path):
    arr = []
    for d in devices:
        ds = device_summary(d)
        arr.append({
            "name": ds["name"],
            "site": ds["site"],
            "role": ds["role"],
            "platform": ds["platform"],
            "vendor": ds["vendor"],
            "device_type": ds["device_type"],
            "mgmt_ip": ds["mgmt_ip"],
        })
    data = {"devices": arr}
    try:
        with open(out_path, "w") as f:
            json.dump(data, f, indent=2)
        return out_path
    except Exception as e:
        print(f"Error writing tfvars to {out_path}: {e}", file=sys.stderr)
        raise

def export_hcl_locals(devices, out_path):
    # Simple HCL locals with a map of devices
    lines = []
    lines.append("locals {")
    lines.append("  devices = {")
    for d in devices:
        ds = device_summary(d)
        name = ds["name"].replace('"', '\"')
        lines.append('    "%s" = {' % name)
        for k in ("site","role","platform","vendor","device_type","mgmt_ip"):
            v = (ds.get(k) or "").replace('"','\"')
            lines.append('      %s = "%s"' % (k, v))
        lines.append("    }")
    lines.append("  }")
    lines.append("}")
    try:
        with open(out_path, "w") as f:
            f.write("\n".join(lines) + "\n")
        return out_path
    except Exception as e:
        print(f"Error writing HCL locals to {out_path}: {e}", file=sys.stderr)
        raise

# -------------------------------
# CLI
# -------------------------------
def main():
    parser = argparse.ArgumentParser(description="NetBox change export → Ansible/Terraform")
    parser.add_argument("--since", help="Relative (24h, 7d) or absolute ISO time", required=True)
    parser.add_argument("--types", nargs="+", default=["device","interface","ip-address"],
                        help="NetBox content types to consider (device, interface, ip-address, ...)")
    parser.add_argument("--site", help="Filter devices by site slug/name")
    parser.add_argument("--role", help="Filter devices by role slug/name")
    parser.add_argument("--tenant", help="Filter devices by tenant")
    parser.add_argument("--tag", help="Filter devices by tag")
    parser.add_argument("--limit", type=int, default=1000, help="Max changes to traverse")
    parser.add_argument("--ansible-out", help="Write Ansible inventory YAML here")
    parser.add_argument("--tfvars-out", help="Write Terraform tfvars JSON here")
    parser.add_argument("--hcl-out", help="Write Terraform HCL locals here")
    parser.add_argument("--dry-run", action="store_true", help="Print changed devices and exit")
    args = parser.parse_args()

    base = os.getenv("NETBOX_URL")
    token = os.getenv("NETBOX_TOKEN")
    verify = env_bool("NETBOX_VERIFY_SSL", True)
    if not base or not token:
        print("ERROR: set NETBOX_URL and NETBOX_TOKEN environment variables", file=sys.stderr)
        sys.exit(2)

    since = parse_since(args.since)
    sess = requests.Session()
    sess.headers.update(headers(token))

    # 1) Get ObjectChanges
    try:
        changes = fetch_object_changes(sess, base, token, since=since, types=[t.lower() for t in args.types],
                                       site=args.site, role=args.role, tenant=args.tenant, tag=args.tag,
                                       limit=args.limit, verify=verify)
        print("Fetched %d ObjectChange rows since %s" % (len(changes), since))
    except Exception as e:
        print(f"Failed to fetch object changes: {e}", file=sys.stderr)
        sys.exit(3)

    # 2) Resolve device IDs
    try:
        dev_ids = resolve_changed_devices(sess, base, token, changes, verify=verify)
        print("Resolved %d device IDs from changes" % (len(dev_ids)))
    except Exception as e:
        print(f"Failed to resolve changed devices: {e}", file=sys.stderr)
        sys.exit(4)
    if not dev_ids:
        print("No impacted devices found; nothing to export.")
        sys.exit(0 if args.dry_run else 1)

    # 3) Fetch device details (apply additional filters if any)
    try:
        devices = fetch_devices(sess, base, token, device_ids=set(dev_ids),
                                site=args.site, role=args.role, tenant=args.tenant, tag=args.tag, verify=verify)
        print("Fetched %d device objects after filters" % (len(devices)))
    except Exception as e:
        print(f"Failed to fetch device objects: {e}", file=sys.stderr)
        sys.exit(5)

    # 4) Dry run
    if args.dry_run and not (args.ansible_out or args.tfvars_out or args.hcl_out):
        for d in devices:
            ds = device_summary(d)
            print("- %(name)s site=%(site)s role=%(role)s mgmt=%(mgmt_ip)s platform=%(platform)s vendor=%(vendor)s" % ds)
        sys.exit(0)

    # 5) Exports
    try:
        if args.ansible_out:
            path = export_ansible(devices, args.ansible_out)
            print("Wrote Ansible inventory:", path)
        if args.tfvars_out:
            path = export_tfvars(devices, args.tfvars_out)
            print("Wrote Terraform tfvars:", path)
        if args.hcl_out:
            path = export_hcl_locals(devices, args.hcl_out)
            print("Wrote Terraform HCL locals:", path)
    except Exception as e:
        print(f"Export failed: {e}", file=sys.stderr)
        sys.exit(6)

if __name__ == "__main__":
    main()
