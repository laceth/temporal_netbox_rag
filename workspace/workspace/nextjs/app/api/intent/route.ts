import { NextRequest } from "next/server";

export async function POST(req: NextRequest) {
  const { text, threadId } = await req.json();
  const API_BASE = process.env.API_BASE || "http://localhost:8000";

  let tid = threadId;
  if (!tid) {
    const t = await fetch(`${API_BASE}/threads`, { method: "POST" });
    const tj = await t.json();
    tid = tj.thread_id;
  }

  const fd = new FormData();
  fd.append("thread_id", tid);
  fd.append("text", text);

  const r = await fetch(`${API_BASE}/message-with-config`, { method: "POST", body: fd });
  const j = await r.json();
  return new Response(JSON.stringify({ ...j, thread_id: tid }), { headers: { "content-type":"application/json" } });
}
