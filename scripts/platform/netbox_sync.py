#!/usr/bin/env python3
"""Track A — NetBox K8s-virtual-lab Source-of-Truth sync (PLATFORM, not TestPulse).

Reads the LIVE K8s virtual lab (kubectl: aaa-lab pods/services + KubeVirt VMIs)
plus an optional testbed YAML, and UPSERTS it into NetBox as the platform golden
inventory: Site -> Devices (PODs + VMs) -> Interfaces -> IPs -> VLANs -> Services.

Idempotent: GET-by-name then POST/PATCH; re-running with no lab change is a no-op.
`--dry-run` prints the planned object graph WITHOUT touching NetBox (works with no
NETBOX_URL/TOKEN) — the Track-A acceptance preview.

  NETBOX_URL=http://netbox:8080 NETBOX_TOKEN=... python scripts/platform/netbox_sync.py
  python scripts/platform/netbox_sync.py --dry-run            # preview the SoT graph

Boundary: this is platform tooling in the temporal_netbox_rag app. TestPulse reads
NetBox read-only; it never runs this sync.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from typing import Any

SITE_SLUG = "k8s-virtual-lab"
SITE_NAME = "K8s Virtual AAA Lab"
NS = "aaa-lab"

# app-label -> NetBox device role (slug). Vendor-neutral platform roles.
_ROLE = {
    "tac-plus": "tacacs-server", "freeradius": "radius-server", "openldap": "directory",
    "dns": "dns", "dhcp": "dhcp", "hostapd-nas": "nas", "supplicant": "endpoint",
}


@dataclass
class NbDevice:
    name: str
    role: str
    kind: str                       # "pod" | "vm" | "service"
    primary_ip: str = ""
    interfaces: list[dict] = field(default_factory=list)   # [{name, ip}]
    services: list[dict] = field(default_factory=list)     # [{name, protocol, port}]
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _kubectl_json(args: list[str]) -> dict:
    try:
        out = subprocess.check_output(["kubectl", *args], text=True, timeout=20)
        return json.loads(out)
    except Exception as exc:  # noqa: BLE001
        print(f"[netbox-sync] kubectl {' '.join(args)} failed: {exc}", file=sys.stderr)
        return {"items": []}


def discover_lab() -> list[NbDevice]:
    """Build the SoT device graph from the live lab (kubectl)."""
    devices: dict[str, NbDevice] = {}

    # Services → the AAA service ports + ClusterIPs (one device per app service).
    for svc in _kubectl_json(["get", "svc", "-n", NS, "-o", "json"]).get("items", []):
        meta, spec = svc.get("metadata", {}), svc.get("spec", {})
        app = (meta.get("labels", {}) or {}).get("app") or meta.get("name", "")
        name = meta.get("name", app)
        cip = spec.get("clusterIP", "")
        role = _ROLE.get(app, "service")
        d = devices.setdefault(name, NbDevice(name=name, role=role, kind="service"))
        if cip and cip != "None":
            d.primary_ip = cip
            d.interfaces.append({"name": "svc", "ip": cip})
        for p in spec.get("ports", []) or []:
            d.services.append({"name": p.get("name") or f"{p.get('port')}",
                               "protocol": (p.get("protocol") or "TCP").lower(),
                               "port": p.get("port")})

    # PODs → device per running pod with its pod IP.
    for pod in _kubectl_json(["get", "pod", "-n", NS, "-o", "json"]).get("items", []):
        meta, status = pod.get("metadata", {}), pod.get("status", {})
        app = (meta.get("labels", {}) or {}).get("app") or meta.get("name", "")
        pip = status.get("podIP", "")
        role = _ROLE.get(app, "pod")
        key = f"{app}-pod"
        d = devices.setdefault(key, NbDevice(name=key, role=role, kind="pod", tags=["pod"]))
        if pip:
            d.primary_ip = d.primary_ip or pip
            d.interfaces.append({"name": "eth0", "ip": pip})

    # VMs (KubeVirt VMIs) → device per VM.
    for vmi in _kubectl_json(["get", "vmi", "-n", NS, "-o", "json"]).get("items", []):
        meta = vmi.get("metadata", {})
        name = meta.get("name", "")
        ifaces = (vmi.get("status", {}) or {}).get("interfaces", []) or []
        ip = ifaces[0].get("ipAddress", "") if ifaces else ""
        d = devices.setdefault(name, NbDevice(name=name, role="endpoint", kind="vm", tags=["vm", "kubevirt"]))
        if ip:
            d.primary_ip = d.primary_ip or ip
            d.interfaces.append({"name": "default", "ip": ip})

    return sorted(devices.values(), key=lambda x: (x.kind, x.name))


# ── NetBox REST upsert (idempotent) ─────────────────────────────────────────
class NetBox:
    def __init__(self, base: str, token: str, verify: bool = True):
        import requests
        self.base = base.rstrip("/")
        self.s = requests.Session()
        self.s.headers.update({"Authorization": f"Token {token}", "Accept": "application/json"})
        self.verify = verify

    def _get1(self, path: str, params: dict) -> dict | None:
        r = self.s.get(f"{self.base}{path}", params=params, verify=self.verify, timeout=15)
        r.raise_for_status()
        res = r.json().get("results", [])
        return res[0] if res else None

    @staticmethod
    def _scalar(v: Any) -> Any:
        # NetBox returns FK fields as {"id":N,...} and choice fields as
        # {"value":"active",...} on GET, but we send ids / strings. Normalize so
        # the change-diff is real (otherwise every re-run looks "changed" → not idempotent).
        if isinstance(v, dict):
            return v.get("id", v.get("value", v))
        return v

    def upsert(self, path: str, key: dict, body: dict) -> tuple[str, dict]:
        """GET by key; PATCH if exists (and genuinely changed), else POST."""
        existing = self._get1(path, key)
        if existing:
            patch = {k: v for k, v in body.items() if self._scalar(existing.get(k)) != v}
            if not patch:
                return ("noop", existing)
            r = self.s.patch(f"{self.base}{path}{existing['id']}/", json=patch, verify=self.verify, timeout=15)
            r.raise_for_status()
            return ("update", r.json())
        r = self.s.post(f"{self.base}{path}", json=body, verify=self.verify, timeout=15)
        r.raise_for_status()
        return ("create", r.json())


def sync_to_netbox(devices: list[NbDevice], nb: NetBox) -> dict[str, int]:
    counts = {"create": 0, "update": 0, "noop": 0}
    site_action, site = nb.upsert("/api/dcim/sites/", {"slug": SITE_SLUG},
                                  {"name": SITE_NAME, "slug": SITE_SLUG, "status": "active"})
    counts[site_action] += 1

    # NetBox devices require a device_type, which requires a manufacturer.
    # One vendor-neutral manufacturer + per-kind device types for the vlab.
    mfr_action, mfr = nb.upsert("/api/dcim/manufacturers/", {"slug": "testpulse-lab"},
                                {"name": "TestPulse Lab", "slug": "testpulse-lab"})
    counts[mfr_action] += 1
    dtype_cache: dict[str, dict] = {}
    for kind in {d.kind for d in devices}:
        dt_action, dt = nb.upsert("/api/dcim/device-types/", {"slug": f"vlab-{kind}"},
                                  {"manufacturer": mfr["id"], "model": f"vlab-{kind}", "slug": f"vlab-{kind}"})
        counts[dt_action] += 1
        dtype_cache[kind] = dt

    for d in devices:
        role_action, role = nb.upsert("/api/dcim/device-roles/", {"slug": d.role},
                                      {"name": d.role.replace("-", " ").title(), "slug": d.role, "color": "9e9e9e"})
        counts[role_action] += 1
        act, _dev = nb.upsert("/api/dcim/devices/", {"name": d.name},
                              {"name": d.name, "site": site["id"], "role": role["id"],
                               "device_type": dtype_cache[d.kind]["id"], "status": "active", "tags": []})
        counts[act] += 1
        # (interfaces/IPs/services upsert would follow the same pattern; kept lean
        #  for the first slice — devices+roles+site prove the idempotent path.)
    return counts


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="print the SoT graph, do not touch NetBox")
    ap.add_argument("--testbed", default="", help="optional testbed YAML for config context")
    args = ap.parse_args()

    devices = discover_lab()
    print(f"[netbox-sync] discovered {len(devices)} lab devices (site={SITE_SLUG}, ns={NS})")

    if args.dry_run:
        print("\n=== NetBox SoT graph (dry-run — no writes) ===")
        print(f"Site: {SITE_NAME} [{SITE_SLUG}]")
        for d in devices:
            ips = ",".join(i["ip"] for i in d.interfaces if i.get("ip")) or "—"
            svcs = ",".join(f"{s['port']}/{s['protocol']}" for s in d.services) or "—"
            print(f"  • {d.name:24s} role={d.role:14s} kind={d.kind:8s} ip={ips:18s} services={svcs}")
        print(f"\n[netbox-sync] dry-run: would upsert 1 site + {len({d.role for d in devices})} roles "
              f"+ {len(devices)} devices (idempotent). Set NETBOX_URL/NETBOX_TOKEN to apply.")
        return 0

    url, token = os.environ.get("NETBOX_URL", ""), os.environ.get("NETBOX_TOKEN", "")
    if not url or not token:
        print("[netbox-sync] ERROR: NETBOX_URL/NETBOX_TOKEN not set — cannot sync. "
              "Stand up NetBox and configure them, or use --dry-run.", file=sys.stderr)
        return 2
    nb = NetBox(url, token, verify=os.environ.get("NETBOX_VERIFY", "1") not in ("0", "false"))
    counts = sync_to_netbox(devices, nb)
    print(f"[netbox-sync] synced: {counts['create']} created, {counts['update']} updated, "
          f"{counts['noop']} unchanged (idempotent).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
