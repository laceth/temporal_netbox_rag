from fastapi import APIRouter, Body
from pydantic import BaseModel
from typing import Dict, Any, Optional, List

from ..intent_engine import classify_intent, extract_entities, plan_from_intent

router = APIRouter(prefix="/intent", tags=["intent"])

class ParseIn(BaseModel):
    text: str
    device_name: Optional[str] = None

class ParseOut(BaseModel):
    intent: str
    entities: Dict[str, Any]

class PlanIn(BaseModel):
    text: Optional[str] = None
    intent: Optional[str] = None
    entities: Optional[Dict[str, Any]] = None
    device_name: Optional[str] = None

class PlanOut(BaseModel):
    intent: str
    vendor_template: str
    entities: Dict[str, Any]
    artifacts: Dict[str, Any]

@router.post("/parse", response_model=ParseOut)
def parse(payload: ParseIn):
    intent = classify_intent(payload.text)
    ents = extract_entities(payload.text)
    if payload.device_name and "device_name" not in ents:
        ents["device_name"] = payload.device_name
    return ParseOut(intent=intent, entities=ents)

@router.post("/plan", response_model=PlanOut)
def plan(payload: PlanIn):
    ents = payload.entities or {}
    if payload.text:
        # merge extracted over provided
        ex = extract_entities(payload.text)
        ex.update(ents)
        ents = ex
    if payload.device_name:
        ents.setdefault("device_name", payload.device_name)
    out = plan_from_intent(ents, device_name=ents.get("device_name"))
    return PlanOut(**out)

@router.get("/vendors", response_model=List[str])
def vendors():
    return ["cisco_ios", "arista_eos", "juniper_junos"]
