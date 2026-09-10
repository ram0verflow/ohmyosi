import { useMemo, useState } from "react";
import { NetworkCanvas } from "./NetworkCanvas";
import { useEvents } from "./hooks/useEvents";
import type { Flow } from "./types";
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
          {pct(stats?.with_name, stats?.live_flows)} · org {pct(stats?.with_org, stats?.live_flows)} · direct-ip{" "}
          {stats?.direct_ip ?? 0}
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
            </div>
          )}
        </aside>
      </div>
    </div>
  );
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
