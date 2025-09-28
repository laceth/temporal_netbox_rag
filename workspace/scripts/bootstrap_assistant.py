#!/usr/bin/env python3
import os, sys, json
from openai import OpenAI

NAME = os.environ.get("ASSISTANT_NAME", "NetOps Intent Router")
MODEL = os.environ.get("ASSISTANT_MODEL", "gpt-4o-mini")  # 4o/4o-mini support tools
INSTRUCTIONS = """You are a NetOps assistant. You:
- Parse user messages into network changes (MOTD, VLAN/port changes)
- When a file is attached, use Code Interpreter to analyze it (CSV, text)
- Always produce a CLI preview block for Cisco IOS.
"""

client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])

def find_by_name(name: str):
    # (API is paginated; this small scan is fine for a handful of assistants)
    page = client.beta.assistants.list(order="desc", limit=20)
    for a in page.data:
        if a.name == name:
            return a
    return None

def main():
    a = find_by_name(NAME)
    if a:
        # ensure required tools are present; update if needed
        tool_types = {t.type for t in (a.tools or [])}
        if not {"code_interpreter", "file_search"}.issubset(tool_types):
            a = client.beta.assistants.update(
                assistant_id=a.id,
                tools=[
                    {"type": "code_interpreter"},
                    {"type": "file_search"},
                ],
                instructions=INSTRUCTIONS,
                model=MODEL,
            )
    else:
        a = client.beta.assistants.create(
            name=NAME,
            model=MODEL,
            instructions=INSTRUCTIONS,
            tools=[
                {"type": "code_interpreter"},
                {"type": "file_search"},
            ],
        )
    print(a.id)  # <- copy this into your .env as ASSISTANT_ID
    # Optional: also print tools for sanity
    print(json.dumps({"assistant_id": a.id, "tools": [t.type for t in a.tools]}, indent=2))

if __name__ == "__main__":
    main()
