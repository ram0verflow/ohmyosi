import { useMemo, useState } from "react";
import { NetworkCanvas } from "./NetworkCanvas";
import { useEvents } from "./hooks/useEvents";
import type { Envelope, Flow } from "./types";
import "./App.css";

export default function App() {
  const { flows, procs, stats, host, connected } = useEvents();
  const [selected, setSelected] = useState<Flow | null>(null);
  const [showSelf, setShowSelf] = useState(false);

  const visible = useMemo(() => {
    const m = new Map<string, Flow>();
    for (const [id, f] of flows) {
      if (!showSelf && f.self) continue;
      m.set(id, f);
    }
    return m;
  }, [flows, showSelf]);

  const top = useMemo(
    () =>
      [...visible.values()]
        .sort((a, b) => b.bytes_up + b.bytes_down - (a.bytes_up + a.bytes_down))
        .slice(0, 8),
    [visible],
  );

  return (
    <div className="app">
      <header className="bar">
        <div className="brand">ohmyosi</div>
        <div className={`dot ${connected ? "on" : ""}`} />
        <div className="meta">
          {host?.hostname ?? "—"} · {stats?.live_flows ?? 0} flows · named{" "}
          {pct(stats?.with_name, stats?.live_flows)} ({stats?.flow_names ?? 0} flow / {stats?.address_names ?? 0}{" "}
          address / {stats?.ambiguous_names ?? 0} ambiguous / {unknownNames(stats)} unknown) · capture{" "}
          {pct(stats?.decoded, stats?.packets)} decoded · pid{" "}
          {pct(stats?.packets_with_process, stats?.packets)} · trunc {stats?.truncated_packets ?? 0} · drops{" "}
          {dropSummary(stats)}
        </div>
        <label className="toggle">
          <input type="checkbox" checked={showSelf} onChange={(e) => setShowSelf(e.target.checked)} />
          self
        </label>
      </header>

      <div className="stage">
        <NetworkCanvas flows={visible} procs={procs} hostname={host?.hostname ?? "Mac"} />
        <aside className="panel">
          <h2>Top connections</h2>
          <ul>
            {top.map((f) => {
              const p = procs.get(f.pid);
              const name = p?.app || p?.name || f.comm;
              const dest = f.remote.host || f.remote.org || f.remote.ip;
              return (
                <li key={f.id} onClick={() => setSelected(f)}>
                  <strong>{name}</strong>
                  <span>{dest}</span>
                  <small>{fmt(f.bytes_up + f.bytes_down)}</small>
                </li>
              );
            })}
          </ul>
          {selected && (
            <div className="detail">
              <h3>{selected.remote.host || selected.remote.ip}</h3>
              {selected.remote.trail?.map((line, i) => (
                <p key={i} className="trail">
                  {line}
                </p>
              ))}
              <p className="evidence">name evidence: {nameEvidence(selected)}</p>
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}

function nameEvidence(flow: Flow) {
  if (flow.remote.name_gap === "dns_ambiguous") {
    return `address-level DNS is ambiguous: ${(flow.remote.name_candidates ?? []).join(", ")}`;
  }
  if (flow.remote.name_scope === "flow") return "flow-specific";
  if (flow.remote.name_scope === "address") return "address-level; shared IPs may be ambiguous";
  switch (flow.remote.name_gap) {
    case "pre_existing":
      return "unknown; connection predates capture";
    case "handshake_name_unavailable":
      return "unknown; handshake absent, unreadable, or encrypted";
    default:
      return "unknown; no name observed";
  }
}

function unknownNames(stats?: Envelope["stats"]) {
  return Math.max(0, (stats?.without_name ?? 0) - (stats?.ambiguous_names ?? 0));
}

function dropSummary(stats?: Envelope["stats"]) {
  if (!stats?.interface_drops_known && !stats?.os_drops_known) return "n/a";
  const values = [];
  if (stats.interface_drops_known) values.push(`${stats.interface_drops} interface`);
  if (stats.os_drops_known) values.push(`${stats.os_drops} OS`);
  return values.join(" / ");
}

function pct(a?: number, b?: number) {
  if (!b) return "—";
  return Math.round(((a ?? 0) / b) * 100) + "%";
}

function fmt(n: number) {
  const u = ["B", "K", "M", "G"];
  let i = 0;
  while (n >= 1024 && i < 3) {
    n /= 1024;
    i++;
  }
  return n.toFixed(i ? 1 : 0) + u[i];
}
