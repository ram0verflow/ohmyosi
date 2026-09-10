import { useEffect, useRef } from "react";
import type { Flow, Proc } from "./types";

type Props = {
  flows: Map<string, Flow>;
  procs: Map<number, Proc>;
  hostname: string;
};

type Node = {
  id: string;
  kind: "machine" | "proc" | "dest";
  label: string;
  sub?: string;
  x: number;
  y: number;
  r: number;
  color: string;
  bytes: number;
};

type Edge = { from: string; to: string; bytes: number; color: string };

function hash(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0) / 4294967295;
}

function hue(s: string) {
  return Math.floor(hash(s) * 360);
}

function destKey(f: Flow): string {
  const r = f.remote;
  return r.domain || r.host || r.org || r.ip;
}

function procKey(f: Flow, procs: Map<number, Proc>): string {
  const p = procs.get(f.pid);
  return p?.app || p?.name || f.comm || `pid ${f.pid}`;
}

export function NetworkCanvas({ flows, procs, hostname }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animRef = useRef(0);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const resize = () => {
      const dpr = window.devicePixelRatio || 1;
      const w = canvas.clientWidth;
      const h = canvas.clientHeight;
      canvas.width = w * dpr;
      canvas.height = h * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    resize();
    window.addEventListener("resize", resize);

    const particles: { edge: number; t: number; speed: number }[] = [];

    const draw = () => {
      const w = canvas.clientWidth;
      const h = canvas.clientHeight;
      const cx = w / 2;
      const cy = h / 2;
      const live = [...flows.values()].filter((f) => !f.self);

      const nodes = new Map<string, Node>();
      const edges: Edge[] = [];

      nodes.set("mac", {
        id: "mac",
        kind: "machine",
        label: hostname || "Mac",
        x: cx,
        y: cy,
        r: 52,
        color: "#e8ecf4",
        bytes: 0,
      });

      const procAngles = new Map<string, number>();
      const destAngles = new Map<string, number>();

      for (const f of live) {
        const pk = procKey(f, procs);
        const dk = destKey(f);
        const bytes = f.bytes_up + f.bytes_down;
        if (!procAngles.has(pk)) procAngles.set(pk, hash(pk) * Math.PI * 2);
        if (!destAngles.has(dk)) destAngles.set(dk, hash(dk) * Math.PI * 2);

        if (!nodes.has("p:" + pk)) {
          const a = procAngles.get(pk)!;
          const pr = Math.min(w, h) * 0.22;
          nodes.set("p:" + pk, {
            id: "p:" + pk,
            kind: "proc",
            label: pk,
            x: cx + Math.cos(a) * pr,
            y: cy + Math.sin(a) * pr,
            r: 28,
            color: `hsl(${hue(pk)} 68% 58%)`,
            bytes: 0,
          });
        }
        nodes.get("p:" + pk)!.bytes += bytes;

        if (!nodes.has("d:" + dk)) {
          const a = destAngles.get(dk)!;
          const dr = Math.min(w, h) * 0.38;
          const r = f.remote;
          const label = r.host || r.org || r.ip;
          const sub = r.host && r.org ? r.org : r.org_detail;
          nodes.set("d:" + dk, {
            id: "d:" + dk,
            kind: "dest",
            label,
            sub,
            x: cx + Math.cos(a) * dr,
            y: cy + Math.sin(a) * dr,
            r: 24 + Math.log10(Math.max(10, bytes)) * 4,
            color: `hsl(${hue(dk)} 42% 62%)`,
            bytes: 0,
          });
        }
        nodes.get("d:" + dk)!.bytes += bytes;

        edges.push({
          from: "p:" + pk,
          to: "d:" + dk,
          bytes,
          color: `hsl(${hue(pk)} 70% 55%)`,
        });
      }

      // Background radial glow
      const bg = ctx.createRadialGradient(cx, cy, 0, cx, cy, Math.max(w, h) * 0.55);
      bg.addColorStop(0, "#1a1f2e");
      bg.addColorStop(0.45, "#0f1219");
      bg.addColorStop(1, "#06080c");
      ctx.fillStyle = bg;
      ctx.fillRect(0, 0, w, h);

      // Edges
      for (const e of edges) {
        const a = nodes.get(e.from);
        const b = nodes.get(e.to);
        if (!a || !b) continue;
        const g = ctx.createLinearGradient(a.x, a.y, b.x, b.y);
        g.addColorStop(0, e.color + "cc");
        g.addColorStop(1, b.color + "99");
        ctx.strokeStyle = g;
        ctx.lineWidth = 1 + Math.log10(Math.max(10, e.bytes)) * 0.6;
        ctx.beginPath();
        const mx = (a.x + b.x) / 2;
        const my = (a.y + b.y) / 2 - 30;
        ctx.moveTo(a.x, a.y);
        ctx.quadraticCurveTo(mx, my, b.x, b.y);
        ctx.stroke();
      }

      // Particles on busiest edges
      if (particles.length < 80) {
        const top = [...edges].sort((x, y) => y.bytes - x.bytes).slice(0, 12);
        for (let i = 0; i < top.length; i++) {
          particles.push({ edge: edges.indexOf(top[i]), t: Math.random(), speed: 0.004 + Math.random() * 0.012 });
        }
      }
      for (const p of particles) {
        p.t += p.speed;
        if (p.t > 1) p.t = 0;
        const e = edges[p.edge];
        if (!e) continue;
        const a = nodes.get(e.from);
        const b = nodes.get(e.to);
        if (!a || !b) continue;
        const t = p.t;
        const mx = (a.x + b.x) / 2;
        const my = (a.y + b.y) / 2 - 30;
        const x = (1 - t) * (1 - t) * a.x + 2 * (1 - t) * t * mx + t * t * b.x;
        const y = (1 - t) * (1 - t) * a.y + 2 * (1 - t) * t * my + t * t * b.y;
        ctx.fillStyle = e.color;
        ctx.beginPath();
        ctx.arc(x, y, 2.2, 0, Math.PI * 2);
        ctx.fill();
      }

      // Nodes
      for (const n of nodes.values()) {
        const glow = ctx.createRadialGradient(n.x, n.y, n.r * 0.2, n.x, n.y, n.r * 1.8);
        glow.addColorStop(0, n.color + "44");
        glow.addColorStop(1, "transparent");
        ctx.fillStyle = glow;
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r * 1.8, 0, Math.PI * 2);
        ctx.fill();

        if (n.kind === "machine") {
          // MacBook silhouette — simplified sun at center
          ctx.fillStyle = "#2a3144";
          ctx.strokeStyle = "#c8d0e0";
          ctx.lineWidth = 2;
          roundRect(ctx, n.x - 44, n.y - 28, 88, 56, 10);
          ctx.fill();
          ctx.stroke();
          ctx.fillStyle = "#0a0c12";
          roundRect(ctx, n.x - 38, n.y - 22, 76, 44, 6);
          ctx.fill();
          ctx.fillStyle = "#e8ecf4";
          ctx.font = "600 13px -apple-system, system-ui, sans-serif";
          ctx.textAlign = "center";
          ctx.fillText(n.label, n.x, n.y + 48);
        } else {
          ctx.fillStyle = n.color;
          ctx.shadowColor = n.color + "66";
          ctx.shadowBlur = 16;
          ctx.beginPath();
          ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
          ctx.fill();
          ctx.shadowBlur = 0;

          ctx.fillStyle = "#f0f3fa";
          ctx.font = `${n.kind === "proc" ? 600 : 500} ${n.kind === "proc" ? 11 : 10}px -apple-system, system-ui, sans-serif`;
          ctx.textAlign = "center";
          const lines = wrap(n.label, 14);
          lines.forEach((line, i) => ctx.fillText(line, n.x, n.y + n.r + 14 + i * 12));
          if (n.sub) {
            ctx.fillStyle = "#8b949e";
            ctx.font = "9px -apple-system, system-ui, sans-serif";
            ctx.fillText(n.sub.slice(0, 22), n.x, n.y + n.r + 14 + lines.length * 12 + 2);
          }
        }
      }

      animRef.current = requestAnimationFrame(draw);
    };

    animRef.current = requestAnimationFrame(draw);
    return () => {
      window.removeEventListener("resize", resize);
      cancelAnimationFrame(animRef.current);
    };
  }, [flows, procs, hostname]);

  return <canvas ref={canvasRef} className="canvas" />;
}

function roundRect(ctx: CanvasRenderingContext2D, x: number, y: number, w: number, h: number, r: number) {
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.arcTo(x + w, y, x + w, y + h, r);
  ctx.arcTo(x + w, y + h, x, y + h, r);
  ctx.arcTo(x, y + h, x, y, r);
  ctx.arcTo(x, y, x + w, y, r);
  ctx.closePath();
}

function wrap(s: string, max: number): string[] {
  if (s.length <= max) return [s];
  return [s.slice(0, max - 1) + "…"];
}
