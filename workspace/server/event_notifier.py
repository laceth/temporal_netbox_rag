#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
event-notifier.py
-----------------
Classic Python 3 (Flask + requests + threading) Event Notifier for a Temporal-orchestrated
NetOps automation flow. It accepts webhooks from NetBox / GitLab (and generic approvals),
verifies HMAC, enqueues processing jobs, calls Temporal (start/signal workflows), and posts
ChatOps notifications (Slack/MS Teams).

Design goals:
- Keep HTTP handlers FAST: verify headers, enqueue, return 202 quickly.
- Do heavy work in a background worker with retries.
- Be explicit, synchronous Python (no asyncio), easy to grok + extend.
- Idempotency + replay protection via event_id cache and timestamps.
- Optional OpenAI summarization hook (RAG/summary) kept separate & fail-safe.

Dependencies (install via pip):
  pip install flask requests python-dotenv

Run:
  export FLASK_APP=event-notifier.py
  python3 event-notifier.py

Config via env (examples):
  SECRET=change_me_shared_hmac
  PORT=8080
  SLACK_WEBHOOK=https://hooks.slack.com/services/T000/B000/XXX
  TEMPORAL_BRIDGE_URL=http://temporal-bridge.internal         # your REST bridge to Temporal
  GITLAB_API=https://gitlab.internal/api/v4
  GITLAB_TOKEN=glpat-...
  ALLOW_NETBOX_IPS=10.0.0.10,10.0.0.11
  ALLOW_GITLAB_IPS=10.0.1.20,10.0.1.21
  OPENAI_API_KEY=... (optional; only used if ENABLE_OPENAI=true)
  ENABLE_OPENAI=false

Notes on Temporal:
- This sample calls a hypothetical REST "temporal-bridge" you expose that wraps
  Temporal signals/start. If you prefer, import temporalio SDK directly inside
  the worker functions (left as TODOs below).

Security:
- HMAC-SHA256 over "{timestamp}.{raw_body}" with header names:
    X-Timestamp: epoch seconds
    X-Signature: sha256=<hex>
- mTLS termination recommended at your frontend proxy (nginx/envoy).
"""
import os
import hmac
import json
import time
import queue
import hashlib
import logging
import threading
from functools import wraps
from secrets import compare_digest

import requests
from flask import Flask, request, jsonify, abort, make_response

# ----------------------------
# Config & Globals
# ----------------------------
SECRET                = os.getenv("SECRET", "change_me_shared_hmac").encode("utf-8")
PORT                  = int(os.getenv("PORT", "8080"))
SLACK_WEBHOOK         = os.getenv("SLACK_WEBHOOK", "")
TEMPORAL_BRIDGE_URL   = os.getenv("TEMPORAL_BRIDGE_URL", "http://localhost:9000")
GITLAB_API            = os.getenv("GITLAB_API", "http://localhost/api/v4")
GITLAB_TOKEN          = os.getenv("GITLAB_TOKEN", "")
ALLOW_NETBOX_IPS      = {ip.strip() for ip in os.getenv("ALLOW_NETBOX_IPS", "").split(",") if ip.strip()}
ALLOW_GITLAB_IPS      = {ip.strip() for ip in os.getenv("ALLOW_GITLAB_IPS", "").split(",") if ip.strip()}
ENABLE_OPENAI         = os.getenv("ENABLE_OPENAI", "false").lower() in {"1","true","yes","y"}
OPENAI_API_KEY        = os.getenv("OPENAI_API_KEY", "")

LOG_LEVEL             = os.getenv("LOG_LEVEL","INFO").upper()
WORKER_THREADS        = int(os.getenv("WORKER_THREADS", "4"))
REPLAY_TTL_SEC        = int(os.getenv("REPLAY_TTL_SEC", "600"))   # remember event ids for 10m

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s %(levelname)s %(message)s")
LOG = logging.getLogger("event-notifier")

app = Flask(__name__)

# Simple in-memory job queue and replay guard
JOBQ = queue.Queue(maxsize=10000)  # type: ignore
_seen = {}  # event_id -> expiry epoch
_seen_lock = threading.RLock()

# ----------------------------
# Helpers
# ----------------------------
def _now():
    return int(time.time())

def verify_hmac(raw, ts, provided):
    try:
        ts_i = int(ts)
    except Exception:
        return False
    # Replay window ±5 minutes
    if abs(_now() - ts_i) > 300:
        return False
    msg = ts.encode() + b"." + raw
    sig = hmac.new(SECRET, msg, hashlib.sha256).hexdigest()
    provided = (provided or "").replace("sha256=", "").strip().lower()
    return compare_digest(sig, provided)

def require_hmac(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        ts = request.headers.get("X-Timestamp", "")
        sig = request.headers.get("X-Signature", "")
        if not ts or not sig:
            abort(make_response(("Missing auth headers", 401)))
        # IMPORTANT: cache=True so later request.get_json() still works
        raw = request.get_data(cache=True, as_text=False)
        if not verify_hmac(raw, ts, sig):
            abort(make_response(("Bad signature or stale timestamp", 401)))
        return f(*args, **kwargs)
    return wrapper

def require_ip(allow):
    def deco(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if allow:
                peer = request.headers.get("X-Forwarded-For", request.remote_addr or "")
                peer = (peer.split(",")[0] or "").strip()
                if peer not in allow:
                    LOG.warning("Denied IP %s for %s", peer, request.path)
                    abort(403)
            return f(*args, **kwargs)
        return wrapper
    return deco

def enqueue_job(job):
    job.setdefault("retries", 0)
    try:
        JOBQ.put(job, timeout=5)
    except queue.Full:
        LOG.exception("Job queue full, dropping job: %s", job)
    except Exception:
        LOG.exception("Unexpected error enqueueing job: %s", job)

def seen_event(event_id):
    if not event_id:
        return False
    with _seen_lock:
        # purge expired
        now = _now()
        for k,v in list(_seen.items()):
            if v < now:
                _seen.pop(k, None)
        if event_id in _seen:
            return True
        _seen[event_id] = now + REPLAY_TTL_SEC
    return False

def backoff_sleep(retries):
    time.sleep(min(60, 2 ** min(8, retries)))  # capped exponential

# ----------------------------
# External Integrations (stubs/simple)
# ----------------------------
def slack_post(blocks=None, text=""):
    if not SLACK_WEBHOOK:
        LOG.info("Slack webhook not configured; skipping")
        return
    payload = {"text": text or "Update", "blocks": blocks or []}
    try:
        r = requests.post(SLACK_WEBHOOK, json=payload, timeout=5)
        if r.status_code >= 300:
            LOG.warning("Slack post failed: %s %s", r.status_code, r.text[:200])
    except Exception as e:
        LOG.exception("Slack post error: %s", e)

def gitlab_mr_comment(project_id, mr_iid, body):
    if not GITLAB_TOKEN:
        LOG.info("GitLab token not set; skipping MR comment")
        return
    url = "%s/projects/%s/merge_requests/%s/notes" % (GITLAB_API, project_id, mr_iid)
    try:
        r = requests.post(url, headers={"PRIVATE-TOKEN": GITLAB_TOKEN}, json={"body": body}, timeout=8)
        if r.status_code >= 300:
            LOG.warning("GitLab MR comment failed: %s %s", r.status_code, r.text[:200])
    except Exception as e:
        LOG.exception("GitLab MR comment error: %s", e)

def temporal_start(change_id, inventory_ref, cohorts):
    url = "%s/changes" % TEMPORAL_BRIDGE_URL
    payload = {"change_id": change_id, "inventory_ref": inventory_ref, "cohorts": cohorts}
    try:
        r = requests.post(url, json=payload, timeout=8)
        if r.status_code >= 300:
            LOG.warning("Temporal start failed: %s %s", r.status_code, r.text[:200])
    except Exception as e:
        LOG.exception("Temporal start error: %s", e)

def temporal_signal(change_id, signal_name, data):
    url = "%s/changes/%s/signal/%s" % (TEMPORAL_BRIDGE_URL, change_id, signal_name)
    try:
        r = requests.post(url, json=data, timeout=8)
        if r.status_code >= 300:
            LOG.warning("Temporal signal failed: %s %s", r.status_code, r.text[:200])
    except Exception as e:
        LOG.exception("Temporal signal error: %s", e)

# Optional OpenAI summarization (disabled by default)
def summarize_event(title, stats, diff_excerpt):
    if not ENABLE_OPENAI or not OPENAI_API_KEY:
        # Basic fallback summary
        return "*%s*\nDevices: %s (changed=%s, failed=%s)" % (
            title,
            stats.get("devices_total","?"),
            stats.get("devices_changed","?"),
            stats.get("devices_failed","0"),
        )
    try:
        headers = {"Authorization": "Bearer %s" % OPENAI_API_KEY}
        prompt = "Summarize for Slack:\nTitle: %s\nStats: %s\nDiff:\n%s" % (
            title, json.dumps(stats), (diff_excerpt or "")[:2000]
        )
        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers=headers,
            json={
                "model": "gpt-4.1-mini",
                "messages": [
                    {"role":"system","content":"You are a concise NetOps notifier; respond in tight bullet points for Slack."},
                    {"role":"user","content": prompt}
                ],
                "temperature": 0.2,
                "max_tokens": 300
            },
            timeout=10
        )
        if resp.status_code >= 300:
            LOG.warning("OpenAI call failed: %s %s", resp.status_code, resp.text[:200])
            return "*%s*\n(see artifacts)" % title
        out = resp.json()["choices"][0]["message"]["content"]
        return out
    except Exception as e:
        LOG.exception("OpenAI summarize error: %s", e)
        return "*%s*\n(see artifacts)" % title

# ----------------------------
# Job processor
# ----------------------------
def process_job(job):
    try:
        kind = job.get("kind")
    except Exception:
        LOG.exception("Malformed job object: %s", job)
        return
    if kind == "netbox.inventory_changed":
        change_id = job["change_id"]
        inventory_ref = job["inventory_ref"]
        cohorts = job.get("cohorts", ["canary"])
        LOG.info("Starting Temporal workflow change_id=%s inv=%s", change_id, inventory_ref)
        temporal_start(change_id, inventory_ref, cohorts)
        slack_post(text=":incoming_envelope: NetBox change detected \u2192 started workflow `%s`" % change_id)
        return

    if kind == "gitlab.run_completed":
        stats = job.get("stats", {})
        change_id = job["change_id"]
        title = "Run completed for change %s" % change_id
        summary = summarize_event(title, stats, job.get("diff_excerpt",""))
        temporal_signal(change_id, "stage_done", {"stats": stats})
        slack_post(text=summary)
        # Optionally comment an MR
        if "gitlab" in job:
            gl = job["gitlab"]
            if gl.get("project_id") and gl.get("mr_iid"):
                gitlab_mr_comment(gl["project_id"], gl["mr_iid"], summary)
        return

    if kind == "approval.signal":
        change_id = job["change_id"]
        approver = job["approver"]
        temporal_signal(change_id, "approve", {"approver": approver})
        slack_post(text=":white_check_mark: Approval received for `%s` by %s" % (change_id, approver))
        return

    LOG.warning("Unknown job kind: %s", kind)

def worker_loop(idx):
    LOG.info("Worker %d started", idx)
    while True:
        try:
            job = JOBQ.get(timeout=1.0)
        except queue.Empty:
            continue
        try:
            process_job(job)
        except Exception as e:
            try:
                job["retries"] = job.get("retries", 0) + 1
            except Exception:
                LOG.exception("Cannot update retries on job: %s", job)
                job = {"kind":"unknown","retries":1}
            LOG.exception("Job error (retry=%s): %s", job.get("retries"), e)
            try:
                if job.get("retries", 0) <= 6:
                    backoff_sleep(job.get("retries", 0))
                    enqueue_job(job)
                else:
                    LOG.error("Dropping job after retries: %s", job)
            except Exception:
                LOG.exception("Error while handling retry logic for job: %s", job)
        finally:
            JOBQ.task_done()

# ----------------------------
# HTTP Handlers
# ----------------------------
@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify({"ok": True, "queue": JOBQ.qsize()})

@app.route("/events/netbox", methods=["POST"])
@require_ip(ALLOW_NETBOX_IPS)  # check and validates IPs from netbox change or add to its DB inventory
@require_hmac
def events_netbox():
    try:
        body = request.get_json(force=True, silent=True) or {}
        event_id = body.get("event_id") or request.headers.get("X-Event-Id", "")
        if seen_event(event_id):
            return ("OK (duplicate ignored)", 200)
        obj = body.get("data", {})
        change_id = body.get("change_id") or "nb-%d" % int(time.time())
        site = obj.get("site", "")
        role = obj.get("role", "")
        inventory_ref = "netbox://site=%s&role=%s" % (site, role)
        cohorts = ["canary", "wave-1", "wave-2"]
        enqueue_job({
            "kind": "netbox.inventory_changed",
            "change_id": change_id,
            "inventory_ref": inventory_ref,
            "cohorts": cohorts,
        })
        return ("Accepted", 202)
    except Exception as e:
        LOG.exception("Error handling netbox event: %s", e)
        return ("Internal Server Error", 500)

@app.route("/events/gitlab", methods=["POST"])
@require_ip(ALLOW_GITLAB_IPS)
@require_hmac
def events_gitlab():
    try:
        body = request.get_json(force=True, silent=True) or {}
        event_id = (body.get("object_attributes") or {}).get("id") or request.headers.get("X-Event-Id", "")
        if seen_event(event_id):
            return ("OK (duplicate ignored)", 200)
        attrs = body.get("object_attributes") or {}
        status = attrs.get("status", "")
        vars_ = attrs.get("variables") or {}
        change_id = vars_.get("CHANGE_ID") or body.get("change_id") or "gl-%d" % int(time.time())
        stats = body.get("stats", {})
        diff_excerpt = body.get("diff_excerpt", "")

        # Optionally include MR coords if sent
        gl = None
        if "project" in body and "merge_request" in body:
            gl = {
                "project_id": (body.get("project") or {}).get("id"),
                "mr_iid": (body.get("merge_request") or {}).get("iid"),
            }

        if status in {"success", "failed"}:
            payload = {
                "kind": "gitlab.run_completed",
                "change_id": change_id,
                "stats": stats,
                "diff_excerpt": diff_excerpt,
            }
            if gl and gl.get("project_id") and gl.get("mr_iid"):
                payload["gitlab"] = gl
            enqueue_job(payload)
        return ("Accepted", 202)
    except Exception as e:
        LOG.exception("Error handling gitlab event: %s", e)
        return ("Internal Server Error", 500)

@app.route("/events/approval", methods=["POST"])
@require_hmac
def events_approval():
    try:
        body = request.get_json(force=True, silent=True) or {}
        change_id = body.get("change_id")
        approver = body.get("approver", "unknown")
        if not change_id:
            abort(make_response(("Missing change_id", 400)))
        enqueue_job({"kind": "approval.signal", "change_id": change_id, "approver": approver})
        return ("Accepted", 202)
    except Exception as e:
        LOG.exception("Error handling approval event: %s", e)
        return ("Internal Server Error", 500)

# ----------------------------
# Startup
# ----------------------------
def _start_workers():
    for i in range(max(1, WORKER_THREADS)):
        t = threading.Thread(target=worker_loop, args=(i,), daemon=True)
        t.start()

if __name__ == "__main__":
    _start_workers()
    LOG.info("Event Notifier listening on 0.0.0.0:%s", PORT)
    app.run(host="0.0.0.0", port=PORT, threaded=True)
