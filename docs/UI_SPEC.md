# UI spec — the canvas

Build against `docs/SCHEMA.md`. Run `sudo ohmyosi`, point a dev server at
`http://127.0.0.1:7777/events`, and check your work against the raw table at
`http://127.0.0.1:7777/`.

## The picture

A single pan/zoom canvas. A MacBook sits at the centre. Connections radiate
outward through the processes that opened them to the places they reach. It
should feel like the product it is competing with on looks — CleanMyMac, Raycast
— which means flat geometry with depth from gradient, shadow and motion, never
skeuomorphic chrome. The MacBook is a clean vector shape, not a rendered
photograph.

```
                                          ┌──────────────┐
                     ╭──────────────────▶ │  cursor.sh   │
                     │                    │  Cloudflare  │
        ┌─────────┐  │                    └──────────────┘
        │ Cursor  │──┤
        └─────────┘  ╰──────────────────▶ ┌──────────────┐
             ▲                            │  Amazon (7)  │
   ┌─────────────────┐                    └──────────────┘
   │                 │
   │    ▓▓▓▓▓▓▓▓▓    │       ┌─────────┐  ┌──────────────┐
   │    ▓ MacBook▓   │──────▶│  Brave  │─▶│  Google (12) │
   │    ▓▓▓▓▓▓▓▓▓    │       └─────────┘  └──────────────┘
   └─────────────────┘            │
                                  ╰─────▶ ┌──────────────┐
                                          │ anthropic.com│
                                          └──────────────┘
```

Three rings: machine, processes, destinations. A destination reached by two
processes is **one node with two edges** — that shared node is the picture a
per-process list cannot draw, and it is the reason this is a graph at all.

## Clustering comes first

114 flows is normal and 400 is not unusual. Drawn one node per flow, the canvas
is a hairball and the premium look is wasted on something unreadable.

So group before you draw, using the fields from `docs/IDENTITY.md`: destinations
collapse by registrable domain (`api2.cursor.sh`, `agentn.global.api5.cursor.sh`
→ one `cursor.sh`) and unnamed addresses collapse by organisation (thirty AWS
IPs → one **Amazon (30)**). Clicking a cluster expands it in place.

Processes group by `app`, not `pid`. A browser is thirty helper processes and
one icon; showing thirty Brave nodes is wrong.

Target for the default view: **under 40 visible nodes**, whatever the flow count.

## Stability is not negotiable

This is where tools in this category fail. EtherApe is the cautionary example: a
force-directed layout rearranges every time a node appears, so everything slides
out from under the cursor. On a laptop opening dozens of connections a second it
reads as a lava lamp, and no amount of gradient rescues that.

1. **No live force simulation.** Position on first sight; never recompute
   because a neighbour arrived.
2. **Deterministic slots.** Hash the app name to an angle. The same app lands in
   the same place every run, so muscle memory works across restarts.
3. **Slots are not reused** for 30s after a node leaves. Closing the gap
   immediately makes everything shuffle.
4. **Animate entry and exit only.** New node scales from 0.8 with opacity at its
   final position; departing node fades over ~2s. Nothing else translates.
5. **Radius from log(total bytes)**, eased slowly, and it must never push
   neighbours.

A boring stable canvas beats a beautiful restless one. When in doubt, freeze it.

## Drawing

- **Canvas or WebGL, not SVG.** 40 nodes with animated edges is fine in SVG; 400
  during an expand is not. PixiJS or plain canvas2d with `requestAnimationFrame`.
- **Edges are quadratic béziers** machine → process → destination, stroked with
  a gradient between the two endpoint colours (`createLinearGradient` along the
  chord).
- **Throughput as motion.** Particles travelling the curve, rate proportional to
  bytes/sec from the diff of consecutive ticks — not cumulative totals, or every
  long-lived flow looks permanently busy. Cap total particles and scale rate, so
  a torrent does not become a strobe.
- **Colour by app**, hue from a hash of the app name so it is stable. Destination
  nodes inherit a desaturated version of whoever talks to them most.
- **Depth** from a soft radial background, one soft shadow per node, and nothing
  else. No borders, no bevels.
- **Numbers in tabular figures** so they stop jittering as they tick.

## Reading the data

- Idle (`last_seen` older than ~10s): drop to 20% opacity, keep the node. The
  daemon decides removal, via `gone`.
- `state: "closed"`: dashed edge until `gone` arrives.
- Name confidence: `sni` and `dns` at full strength, `rdns` dimmed, no name at
  all as the organisation from ASN, and a bare IP in monospace as last resort.
- `self: true`: hidden behind a toggle, off by default.
- **First sighting**: a process/destination pair never seen before gets a
  quiet ring. This is presentation, not detection — see the malware note in
  `docs/IDENTITY.md`.

## Interactions

- Hover a node: light its edges, dim the rest.
- Click a process: side panel with full path, bundle ID, every PID under that
  app, and destinations sorted by bytes.
- Click a destination: who reaches it, since when, on what ports, how the name
  was learned, and the org/ASN/country underneath.
- Click a cluster: expand in place, siblings make room without the layout
  reflowing globally.
- Search: non-matching nodes fall to 10% opacity rather than disappearing, so
  nothing moves.
- **Pause**: freeze the view, keep buffering. Essential — things scroll past
  faster than you can click.

## What must be answerable without clicking

Someone opening this is asking one question: *what is my machine talking to that
I did not expect?* Sort visual weight by bytes, keep unnamed destinations
visible rather than tucked away, and make app names legible at rest.

## Not in v1

Blocking, packet-level inspection, per-browser-tab attribution, geographic maps
(pretty, low information density, and the IP-to-location data is poor), timeline
scrubbing. Get live right first.
