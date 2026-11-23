// Parallel browsing lanes for the ohmyosi measurement.
//
// Each lane is an independent browser instance (its own process tree and a
// fresh throwaway profile) that visits its own share of a fixed site list.
// Lanes run at the same time, so one capture covers many sites, and pktap
// still tells the lanes apart by process. Instances, not tabs: tabs inside
// one browser share a connection pool and host cache, which would blur the
// per-flow evidence.
//
//   node lanes.mjs --sites list.txt --browsers chrome:4,firefox:2 --doh on \
//                  --dwell 6 --out dist/runs/<base> [--safari] [--dry-run]
//
// Writes <out>.visits.tsv (ms \t lane \t site, one line per visit, written
// just before navigating) and <out>.lanes.json (lane -> browser, version,
// shard size and every PID its process tree had, sampled every 10 s).
// Installed browsers are driven, never patched builds: Chrome through
// puppeteer-core, Firefox through WebDriver BiDi, Safari through
// safaridriver (one lane: Safari allows one automation session).

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import puppeteer from "puppeteer-core";

const CHROME = process.env.CHROME_PATH || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const FIREFOX = process.env.FIREFOX_PATH || "/Applications/Firefox.app/Contents/MacOS/firefox";
const DOH_CHROME = "https://cloudflare-dns.com/dns-query";
const DOH_FIREFOX = "https://mozilla.cloudflare-dns.com/dns-query";

function args() {
  const a = { browsers: "chrome:4,firefox:2", doh: "off", dwell: 6, safari: false, dryRun: false, timeout: 20 };
  const v = process.argv.slice(2);
  for (let i = 0; i < v.length; i++) {
    const k = v[i];
    const next = () => v[++i];
    if (k === "--sites") a.sites = next();
    else if (k === "--browsers") a.browsers = next();
    else if (k === "--doh") a.doh = next();
    else if (k === "--dwell") a.dwell = Number(next());
    else if (k === "--out") a.out = next();
    else if (k === "--timeout") a.timeout = Number(next());
    else if (k === "--safari") a.safari = true;
    else if (k === "--dry-run") a.dryRun = true;
    else throw new Error(`unknown argument ${k}`);
  }
  if (!a.sites || !a.out) throw new Error("--sites and --out are required");
  if (!["on", "off"].includes(a.doh)) throw new Error("--doh must be on or off");
  return a;
}

// Lanes in a fixed order; site i goes to lane i mod N (deterministic shards).
export function planLanes(spec, safari) {
  const lanes = [];
  for (const part of spec.split(",").filter(Boolean)) {
    const [browser, n] = part.split(":");
    for (let i = 1; i <= Number(n || 1); i++) lanes.push({ id: `${browser}-${i}`, browser });
  }
  if (safari) lanes.push({ id: "safari-1", browser: "safari" });
  return lanes;
}

export function shard(sites, lanes) {
  const out = new Map(lanes.map((l) => [l.id, []]));
  sites.forEach((s, i) => out.get(lanes[i % lanes.length].id).push(s));
  return out;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function version(app) {
  try {
    return execFileSync("defaults", ["read", `${app}/Contents/Info`, "CFBundleShortVersionString"]).toString().trim();
  } catch {
    return "unknown";
  }
}

// Every descendant of root, from one ps snapshot.
function descendants(root) {
  const out = new Set([root]);
  let rows;
  try {
    rows = execFileSync("ps", ["-A", "-o", "pid=,ppid="]).toString().trim().split("\n");
  } catch {
    return out;
  }
  const kids = new Map();
  for (const r of rows) {
    const [pid, ppid] = r.trim().split(/\s+/).map(Number);
    if (!kids.has(ppid)) kids.set(ppid, []);
    kids.get(ppid).push(pid);
  }
  const stack = [root];
  while (stack.length) {
    for (const k of kids.get(stack.pop()) || []) {
      if (!out.has(k)) {
        out.add(k);
        stack.push(k);
      }
    }
  }
  return out;
}

async function launch(lane, doh) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `ohmyosi-${lane.id}-`));
  lane.profile = dir;
  if (lane.browser === "chrome") {
    // Chrome reads its DoH mode from Local State (same as tools/workload/run.sh).
    const mode = doh === "on" ? "secure" : "off";
    fs.writeFileSync(path.join(dir, "Local State"), JSON.stringify({ dns_over_https: { mode, templates: DOH_CHROME } }));
    lane.version = version("/Applications/Google Chrome.app");
    return puppeteer.launch({
      executablePath: CHROME, headless: true, userDataDir: dir,
      // CHROME_ARGS: extra flags, for testing outside macOS only.
      args: ["--no-first-run", "--no-default-browser-check", ...(process.env.CHROME_ARGS || "").split(" ").filter(Boolean)],
    });
  }
  if (lane.browser === "firefox") {
    lane.version = version("/Applications/Firefox.app");
    return puppeteer.launch({
      browser: "firefox", executablePath: FIREFOX, headless: true, userDataDir: dir,
      extraPrefsFirefox: {
        "network.trr.mode": doh === "on" ? 3 : 5, // 3 = DoH only; 5 = explicitly off
        "network.trr.uri": DOH_FIREFOX,
        "datareporting.policy.dataSubmissionEnabled": false,
      },
    });
  }
  throw new Error(`no launcher for ${lane.browser}`);
}

// Safari through safaridriver's WebDriver HTTP API (one session at a time;
// automation sessions use a fresh private profile, so Safari runs truly cold).
async function safariLane(lane, sites, a, log) {
  const port = 4444 + Math.floor(Math.random() * 1000);
  const { spawn } = await import("node:child_process");
  const drv = spawn("/usr/bin/safaridriver", ["-p", String(port)], { stdio: "ignore" });
  lane.version = version("/Applications/Safari.app");
  lane.rootPid = drv.pid;
  await sleep(1500);
  const base = `http://127.0.0.1:${port}`;
  const call = async (method, p, body) => {
    const r = await fetch(base + p, { method, headers: { "content-type": "application/json" }, body: body && JSON.stringify(body) });
    return r.json();
  };
  try {
    const s = await call("POST", "/session", { capabilities: { alwaysMatch: { browserName: "safari" } } });
    const id = s.value?.sessionId;
    if (!id) throw new Error(`safaridriver: ${JSON.stringify(s.value)}`);
    for (const site of sites) {
      log(lane.id, site);
      const r = await Promise.race([
        call("POST", `/session/${id}/url`, { url: `https://${site}/` }),
        sleep(a.timeout * 1000).then(() => ({ value: { error: "timeout" } })),
      ]);
      lane.visits.push({ site, outcome: r.value?.error || "ok" });
      await sleep(a.dwell * 1000);
    }
    await call("DELETE", `/session/${id}`);
  } finally {
    drv.kill();
  }
}

async function runLane(lane, sites, a, log) {
  lane.visits = [];
  if (lane.browser === "safari") return safariLane(lane, sites, a, log);
  const browser = await launch(lane, a.doh);
  lane.rootPid = browser.process()?.pid;
  const page = await browser.newPage();
  try {
    for (const site of sites) {
      log(lane.id, site);
      let outcome = "ok";
      try {
        await page.goto(`https://${site}/`, { waitUntil: "domcontentloaded", timeout: a.timeout * 1000 });
      } catch (e) {
        outcome = String(e.message || e).split("\n")[0];
      }
      lane.visits.push({ site, outcome });
      await sleep(a.dwell * 1000);
    }
  } finally {
    await browser.close().catch(() => {});
    fs.rmSync(lane.profile, { recursive: true, force: true });
  }
}

async function main() {
  const a = args();
  const sites = fs.readFileSync(a.sites, "utf8").split("\n").map((s) => s.trim()).filter(Boolean);
  const lanes = planLanes(a.browsers, a.safari);
  const shards = shard(sites, lanes);
  if (a.dryRun) {
    console.log(`plan: ${sites.length} sites over ${lanes.length} lanes, DoH ${a.doh}, dwell ${a.dwell}s`);
    for (const l of lanes) console.log(`  ${l.id.padEnd(10)} ${shards.get(l.id).length} sites, first: ${shards.get(l.id).slice(0, 3).join(", ")}`);
    const longest = Math.max(...lanes.map((l) => shards.get(l.id).length));
    console.log(`  ~${Math.ceil((longest * (a.dwell + 2)) / 60)} min wall time`);
    return;
  }
  const visits = fs.openSync(`${a.out}.visits.tsv`, "a");
  const log = (lane, site) => fs.writeSync(visits, `${Date.now()}\t${lane}\t${site}\n`);

  const pids = new Map(lanes.map((l) => [l.id, new Set()]));
  const sample = () => {
    for (const l of lanes) if (l.rootPid) for (const p of descendants(l.rootPid)) pids.get(l.id).add(p);
  };
  const timer = setInterval(sample, 10_000);
  const sampleSoon = setInterval(sample, 1_000); // catch helpers that start early
  setTimeout(() => clearInterval(sampleSoon), 15_000);

  const results = await Promise.allSettled(lanes.map((l) => runLane(l, shards.get(l.id), a, log)));
  clearInterval(timer);
  sample();
  fs.closeSync(visits);

  const out = lanes.map((l, i) => ({
    id: l.id, browser: l.browser, version: l.version || "unknown", doh: l.browser === "safari" ? "off" : a.doh,
    sites: shards.get(l.id).length,
    ok: (l.visits || []).filter((v) => v.outcome === "ok").length,
    failed: (l.visits || []).filter((v) => v.outcome !== "ok").length,
    error: results[i].status === "rejected" ? String(results[i].reason?.message || results[i].reason) : undefined,
    pids: [...pids.get(l.id)].sort((x, y) => x - y),
  }));
  fs.writeFileSync(`${a.out}.lanes.json`, JSON.stringify(out, null, 2));
  for (const l of out) console.log(`${l.id}: ${l.ok}/${l.sites} ok${l.error ? `, ERROR ${l.error}` : ""}, ${l.pids.length} pids`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => {
    console.error(e.message || e);
    process.exit(1);
  });
}
