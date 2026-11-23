# Real firewalls alongside the measurement

Goal: score what Little Snitch and LuLu **actually display** for each
connection, against ground truth (challenge runs) and against the handshake
name (browsing runs), exactly like the modelled strategies. A tool's log next
to a capture, `<capture>.<tool>.csv`, becomes strategy `real:<tool>` in
`ohmyosi -eval` and `make report`.

Run **one firewall at a time**. Set it to **allow everything** so it records
but never changes the traffic under test.

## Little Snitch 6 (automated export)

1. Install Little Snitch 6 (demo mode is fine: it runs for a few hours per
   launch, enough for a run). Approve its system extension in
   System Settings > General > Login Items & Extensions > Network Extensions.
2. Settings > Security: turn on **"Allow access via Terminal"** (required for
   the `littlesnitch` command). Leave **"Verify server names asserted by
   process"** at its default (on), and record if you change it.
3. Allow everything. Use the **Silent Mode – allow connections** option, or an
   allow-all rule profile, so no alert blocks a flow.
4. Check the CLI: `sudo littlesnitch log-traffic -b "$(date -v-5M '+%Y-%m-%d %H:%M:%S')"`
   should print CSV with a header `date,direction,uid,ipAddress,remoteHostname,…`.
   If `littlesnitch` is not on PATH, find it under
   `/Applications/Little Snitch.app/Contents/` and tell the agent the path.
5. Runs: `make challenge NETWORK=home FIREWALL=littlesnitch REPS=50` and/or
   `sudo make parallel NETWORK=home FIREWALL=littlesnitch …`. The export runs
   automatically for the capture window (`tools/realtools/export.sh`).

Docs: https://help.obdev.at/littlesnitch6/cmd-log-traffic ·
https://help.obdev.at/littlesnitch6/cmd-overview ·
FAQ on server-name verification: https://www.obdev.at/support/littlesnitch

Caveat for the write-up: `log-traffic` rows are **per interval, not per
connection**. The importer joins a row to a flow by remote address, port,
protocol, executable and a ±2 min window; ambiguous joins are possible when
one executable reaches one address under several names within an interval.

## LuLu (semi-automated)

LuLu names a connection with the host name macOS itself supplies to the
Network Extension (`flow.URL.host`, then `remoteHostname`, then the endpoint's
hostname; see `LuLu/Extension/FilterDataProvider.m`). That is Little Snitch's
step 1, which packets alone can't show, so LuLu runs tell us **how often macOS
hands over a name at all**.

1. Install LuLu (https://objective-see.org/products/lulu.html), approve its
   extension, quit or disable Little Snitch first.
2. Enable **Passive Mode** (allow, don't prompt) so it never blocks.
3. Runs: `make challenge NETWORK=home FIREWALL=lulu REPS=50`. `export.sh`
   saves the raw unified log for the window as `<capture>.lulu.raw.ndjson`
   (`log show … --predicate 'subsystem == "com.objective-see.lulu"'`).
4. **To do (agent):** look at that raw log. LuLu's debug line is
   `[LULU] PROCESS: <path>, FLOW (endpoint): <ip:port>, RULE: …, verdict: …`.
   Find whether a host name is logged per flow. If yes, convert to
   `<capture>.lulu.csv` with columns `time,executable,ip,port,protocol,name`
   (time = unix ms or `YYYY-MM-DD HH:MM:SS`). If not, record that LuLu's
   displayed name is not exportable and use its rules list (host names it
   created rules for) only as a qualitative check.

## Not on macOS

Portmaster and OpenSnitch are Windows/Linux only. A UTM Linux VM running the
challenge suite is a stretch goal; don't start it before the macOS runs are done.
