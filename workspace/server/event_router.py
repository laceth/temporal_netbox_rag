from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import os, hmac, hashlib, uuid, time, json, pathlib, threading

app = FastAPI(title="Event Router", version="1.0.0")

# HMAC secret (set SECRET env var in prod)
SECRET = os.getenv("SECRET", "dev_shared_secret").encode("utf-8")

# replay guard
_seen = {}
_seen_lock = threading.RLock()
REPLAY_TTL_SEC = int(os.getenv("REPLAY_TTL_SEC", "600"))

ART_DIR = pathlib.Path(os.getenv("ART_DIR", "/mnt/data/artifacts"))
ART_DIR.mkdir(parents=True, exist_ok=True)

def _purge_seen(now:int):
    for k,v in list(_seen.items()):
        if v < now:
            _seen.pop(k, None)

def verify(sig, body: bytes):
    # Expect header: X-Hub-Signature-256: sha256=<hex>
    if not sig:
        return False
    sig = sig.replace("sha256=", "").strip().lower()
    mac = hmac.new(SECRET, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, sig)

@app.get("/healthz")
async def healthz():
    return {"ok": True, "seen": len(_seen)}

@app.post("/webhook/netbox")
async def netbox_hook(req: Request):
    body = await req.body()
    sig  = req.headers.get("X-Hub-Signature-256", "")
    if not verify(sig, body):
        raise HTTPException(401, "bad signature")

    try:
        payload = await req.json()
    except Exception:
        raise HTTPException(400, "invalid json")

    event_id = payload.get("event_id") or req.headers.get("X-Event-Id") or str(uuid.uuid4())
    ts = int(time.time())

    # dedupe/idempotency
    with _seen_lock:
        _purge_seen(ts)
        if event_id in _seen:
            return JSONResponse({"status":"duplicate", "event_id": event_id}, status_code=200)
        _seen[event_id] = ts + REPLAY_TTL_SEC

    # correlation id
    corr = str(uuid.uuid4())

    # persist intake artifacts
    corr_dir = ART_DIR / corr
    corr_dir.mkdir(parents=True, exist_ok=True)
    (corr_dir / "payload.json").write_text(json.dumps(payload, indent=2))
    meta = {
        "correlation_id": corr,
        "event_id": event_id,
        "received_at": ts,
        "source": "netbox",
        "validated": True
    }
    (corr_dir / "intake.json").write_text(json.dumps(meta, indent=2))

    # stub “start workflow” message (replace with real Temporal call)
    start_msg = {
        "action": "start_workflow",
        "workflow": "inventory_changed",
        "input": {"correlation_id": corr, "payload_ref": str((corr_dir / "payload.json"))}
    }
    (corr_dir / "start.json").write_text(json.dumps(start_msg, indent=2))

    return {"status":"accepted", "correlation_id": corr, "event_id": event_id}
