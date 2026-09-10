import { useEffect, useState } from "react";
import type { Envelope, Flow, Proc } from "../types";

export function useEvents(url = "/events") {
  const [flows, setFlows] = useState<Map<string, Flow>>(new Map());
  const [procs, setProcs] = useState<Map<number, Proc>>(new Map());
  const [stats, setStats] = useState<Envelope["stats"]>();
  const [host, setHost] = useState<Envelope["host"]>();
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    const es = new EventSource(url);
    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);
    es.onmessage = (ev) => {
      const m: Envelope = JSON.parse(ev.data);
      if (m.host) setHost(m.host);
      if (m.stats) setStats(m.stats);
      setProcs((prev) => {
        const next = new Map(prev);
        for (const p of m.procs ?? []) next.set(p.pid, p);
        return next;
      });
      setFlows((prev) => {
        const next = new Map(prev);
        for (const f of m.flows ?? []) next.set(f.id, f);
        for (const id of m.gone ?? []) next.delete(id);
        return next;
      });
    };
    return () => es.close();
  }, [url]);

  return { flows, procs, stats, host, connected };
}
