import os
import requests
from typing import Optional, Dict, Any, List

class NetBoxClient:
    """Very small NetBox REST wrapper used by the intent engine.

    Env:
      NETBOX_URL
      NETBOX_TOKEN
      NETBOX_VERIFY_SSL (default 1)
    """
    def __init__(self, base_url: Optional[str]=None, token: Optional[str]=None, verify: Optional[bool]=None):
        self.base = (base_url or os.environ.get("NETBOX_URL", "")).rstrip("/")
        self.token = token or os.environ.get("NETBOX_TOKEN", "")
        vs = os.environ.get("NETBOX_VERIFY_SSL", "1")
        self.verify = verify if verify is not None else (vs not in ["0","false","False"])
        self.session = requests.Session()
        if self.token:
            self.session.headers["Authorization"] = f"Token {self.token}"

    def ok(self) -> bool:
        return bool(self.base)

    def _get(self, path: str, params: Dict[str, Any]=None) -> Dict[str, Any]:
        url = f"{self.base}{path}"
        r = self.session.get(url, params=params or {}, verify=self.verify, timeout=20)
        r.raise_for_status()
        return r.json()

    def get_device(self, name: str) -> Optional[Dict[str, Any]]:
        if not self.ok(): return None
        data = self._get("/api/dcim/devices/", params={"name": name})
        results = data.get("results", [])
        return results[0] if results else None

    def get_device_vendor(self, name: str) -> Optional[str]:
        dev = self.get_device(name)
        if not dev: return None
        mfg = (((dev.get("device_type") or {}).get("manufacturer") or {}).get("name") or "")
        return mfg.lower() or None

    def get_site(self, slug: str) -> Optional[Dict[str, Any]]:
        if not self.ok(): return None
        data = self._get("/api/dcim/sites/", params={"slug": slug})
        results = data.get("results", [])
        return results[0] if results else None

    def get_vlans(self, ids: List[int]) -> List[Dict[str, Any]]:
        if not self.ok() or not ids: return []
        # simple filter by id list
        params = [("id", vid) for vid in ids]
        url = f"{self.base}/api/ipam/vlans/"
        r = self.session.get(url, params=params, verify=self.verify, timeout=20)
        r.raise_for_status()
        return r.json().get("results", [])
