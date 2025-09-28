import json, time, os
from typing import Any, Dict, Optional
from fastapi import APIRouter
from pydantic import BaseModel
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()
client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

router = APIRouter(prefix="/intent/llm", tags=["intent-llm"])

INTENT_ASSISTANT_NAME = os.environ.get("INTENT_ASSISTANT_NAME", "NetOps Intent LLM")
INTENT_ASSISTANT_MODEL = os.environ.get("INTENT_ASSISTANT_MODEL", "gpt-4o-mini")

EMIT_INTENT_SCHEMA: Dict[str, Any] = {
    "name": "emit_intent",
    "description": "Emit a structured NetOps intent JSON for switch/router bootstrap or config change.",
    "parameters": {
        "type": "object",
        "properties": {
            "intent": {"type": "string"},
            "entities": {"type": "object", "additionalProperties": True},
            "dry_run": {"type":"boolean", "default": True}
        },
        "required": ["intent","entities"]
    }
}

def ensure_intent_assistant() -> str:
    page = client.beta.assistants.list(order="desc", limit=20)
    for a in page.data:
        if a.name == INTENT_ASSISTANT_NAME:
            has_fn = any((getattr(t, "type", None) == "function" and getattr(getattr(t, "function", None), "name", None) == "emit_intent") for t in (a.tools or []))
            if not has_fn:
                a = client.beta.assistants.update(
                    assistant_id=a.id,
                    model=INTENT_ASSISTANT_MODEL,
                    tools=[{"type":"function","function":EMIT_INTENT_SCHEMA}]
                )
            return a.id
    a = client.beta.assistants.create(
        name=INTENT_ASSISTANT_NAME,
        model=INTENT_ASSISTANT_MODEL,
        instructions=(
            "You are a NetOps NLU assistant. Read the user's request and call the emit_intent function exactly once "
            "with a normalized JSON. Expand VLAN ranges like 37-40. Do not write prose; only call the function."
        ),
        tools=[{"type":"function","function":EMIT_INTENT_SCHEMA}]
    )
    return a.id

class LLMParseIn(BaseModel):
    text: str
    thread_id: Optional[str] = None

class LLMParseOut(BaseModel):
    assistant_id: str
    thread_id: str
    run_id: str
    status: str
    emitted: Optional[Dict[str, Any]] = None
    tool_call_id: Optional[str] = None
    assistant_message_id: Optional[str] = None

def poll(thread_id: str, run_id: str):
    while True:
        r = client.beta.threads.runs.retrieve(thread_id=thread_id, run_id=run_id)
        if r.status in ("completed","failed","cancelled","expired"):
            return r
        if r.status == "requires_action":
            return r
        time.sleep(0.4)

@router.post("/parse", response_model=LLMParseOut)
def llm_parse(payload: LLMParseIn):
    aid = ensure_intent_assistant()
    tid = payload.thread_id or client.beta.threads.create().id
    client.beta.threads.messages.create(thread_id=tid, role="user", content=payload.text)
    run = client.beta.threads.runs.create(thread_id=tid, assistant_id=aid)
    r = poll(tid, run.id)

    emitted = None
    tool_call_id = None

    if r.status == "requires_action":
        calls = r.required_action.submit_tool_outputs.tool_calls
        for tc in calls:
            if tc.type == "function" and tc.function.name == "emit_intent":
                tool_call_id = tc.id
                try:
                    emitted = json.loads(tc.function.arguments)
                except Exception:
                    emitted = {"_raw_args": tc.function.arguments}
                client.beta.threads.runs.submit_tool_outputs(
                    thread_id=tid, run_id=run.id,
                    tool_outputs=[{"tool_call_id": tc.id, "output": "ok"}]
                )
        r = poll(tid, run.id)

    msgs = client.beta.threads.messages.list(thread_id=tid, order="desc", limit=5)
    asst_msg_id = None
    for m in msgs.data:
        if m.role == "assistant":
            asst_msg_id = m.id
            break

    return LLMParseOut(
        assistant_id=aid, thread_id=tid, run_id=run.id,
        status=r.status, emitted=emitted, tool_call_id=tool_call_id,
        assistant_message_id=asst_msg_id
    )
