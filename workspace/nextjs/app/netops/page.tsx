"use client";
import { useState, useRef, useEffect } from "react";

interface Message {
  role: "user" | "assistant";
  text: string;
  cli?: string;
  intent?: string;
}

export default function Page() {
  const [messages, setMessages] = useState<Message[]>([
    { role: "assistant", text: "NetOps AI ready. Ask me to bootstrap a device, configure VLANs, or generate CLI configs for Cisco, Arista, or Juniper." }
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [threadId, setThreadId] = useState<string | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: "smooth" }); }, [messages]);

  async function send() {
    const text = input.trim();
    if (!text || loading) return;
    setInput("");
    setMessages(m => [...m, { role: "user", text }]);
    setLoading(true);
    try {
      const res = await fetch("/api/intent", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ text, threadId }),
      });
      const data = await res.json();
      if (data.thread_id) setThreadId(data.thread_id);

      const cli = data.artifacts?.cli_preview || data.emitted?.cli_preview || null;
      const intent = data.intent || data.emitted?.intent || null;
      const reply = data.reply || data.status || (intent ? `Intent: ${intent}` : "Processed.");

      setMessages(m => [...m, { role: "assistant", text: reply, cli, intent }]);
    } catch {
      setMessages(m => [...m, { role: "assistant", text: "Error contacting backend. Check logs." }]);
    }
    setLoading(false);
  }

  return (
    <main style={{ display: "flex", flexDirection: "column", height: "100vh", fontFamily: "monospace", background: "#0d1117", color: "#e6edf3" }}>
      <header style={{ padding: "12px 20px", background: "#161b22", borderBottom: "1px solid #30363d", fontSize: 14, fontWeight: 700, letterSpacing: 1 }}>
        NetOps AI — Netbox RAG Assistant
      </header>

      <div style={{ flex: 1, overflowY: "auto", padding: "16px 20px", display: "flex", flexDirection: "column", gap: 12 }}>
        {messages.map((m, i) => (
          <div key={i} style={{ display: "flex", flexDirection: "column", alignItems: m.role === "user" ? "flex-end" : "flex-start", gap: 4 }}>
            <div style={{
              maxWidth: "75%", padding: "10px 14px", borderRadius: 8, fontSize: 13, lineHeight: 1.6,
              background: m.role === "user" ? "#1f6feb" : "#21262d",
              border: m.role === "assistant" ? "1px solid #30363d" : "none",
            }}>
              {m.intent && <div style={{ fontSize: 11, color: "#8b949e", marginBottom: 4 }}>intent: {m.intent}</div>}
              {m.text}
            </div>
            {m.cli && (
              <pre style={{
                maxWidth: "75%", margin: 0, padding: "12px 14px", borderRadius: 8, fontSize: 12,
                background: "#0d1117", border: "1px solid #238636", color: "#3fb950", overflowX: "auto"
              }}>
                {m.cli}
              </pre>
            )}
          </div>
        ))}
        {loading && (
          <div style={{ alignSelf: "flex-start", padding: "10px 14px", background: "#21262d", borderRadius: 8, fontSize: 13, color: "#8b949e" }}>
            thinking...
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      <div style={{ padding: "12px 16px", background: "#161b22", borderTop: "1px solid #30363d", display: "flex", gap: 8 }}>
        <input
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === "Enter" && send()}
          placeholder="e.g. Bootstrap a Cisco switch at site NYC, mgmt IP 10.2.1.1, VLANs 10,20,30"
          style={{
            flex: 1, padding: "10px 14px", borderRadius: 6, border: "1px solid #30363d",
            background: "#0d1117", color: "#e6edf3", fontSize: 13, outline: "none"
          }}
        />
        <button
          onClick={send}
          disabled={loading}
          style={{
            padding: "10px 20px", borderRadius: 6, border: "none", cursor: loading ? "not-allowed" : "pointer",
            background: loading ? "#21262d" : "#238636", color: "#fff", fontSize: 13, fontWeight: 600
          }}
        >
          Send
        </button>
      </div>
    </main>
  );
}
