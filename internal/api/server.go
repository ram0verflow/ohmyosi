package api

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// Server fans one stream of envelopes out to any number of SSE clients.
//
// SSE rather than WebSocket on purpose: this stream is strictly one-way, SSE
// needs no dependency beyond net/http, and EventSource reconnects on its own,
// so a UI survives a daemon restart without any reconnect logic.
type Server struct {
	mu      sync.RWMutex
	clients map[chan []byte]bool

	hello      func() Envelope // full state for a newly connected client
	iconDir    string
	faviconDir string
}

func NewServer(hello func() Envelope, iconDir, faviconDir string) *Server {
	return &Server{clients: make(map[chan []byte]bool), hello: hello,
		iconDir: iconDir, faviconDir: faviconDir}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/events", s.events)
	mux.HandleFunc("/api/snapshot", s.snapshot)
	mux.Handle("/icons/", http.StripPrefix("/icons/", http.FileServer(http.Dir(s.iconDir))))
	if s.faviconDir != "" {
		mux.Handle("/favicons/", http.StripPrefix("/favicons/", http.FileServer(http.Dir(s.faviconDir))))
	}
	mux.HandleFunc("/", s.index)
	return mux
}

// Broadcast sends an envelope to every client. Slow clients are dropped rather
// than allowed to stall the tick loop: a wedged browser tab must never apply
// back-pressure to packet capture.
func (s *Server) Broadcast(e Envelope) {
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for ch := range s.clients {
		select {
		case ch <- b:
		default:
		}
	}
}

func (s *Server) Clients() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.clients)
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*") // so a Vite dev server can attach

	ch := make(chan []byte, 32)
	s.mu.Lock()
	s.clients[ch] = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.clients, ch)
		s.mu.Unlock()
	}()

	if b, err := json.Marshal(s.hello()); err == nil {
		w.Write([]byte("data: "))
		w.Write(b)
		w.Write([]byte("\n\n"))
		flusher.Flush()
	}

	keepalive := time.NewTicker(20 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case b := <-ch:
			w.Write([]byte("data: "))
			w.Write(b)
			w.Write([]byte("\n\n"))
			flusher.Flush()
		case <-keepalive.C:
			w.Write([]byte(": ping\n\n"))
			flusher.Flush()
		}
	}
}

func (s *Server) snapshot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(s.hello())
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(debugPage))
}

// debugPage is deliberately ugly. It exists to prove the pipe works before any
// real UI is written, and to be the thing you open when the graph looks wrong
// and you need to see what the daemon actually said.
const debugPage = `<!doctype html>
<meta charset="utf-8"><title>ohmyosi - raw</title>
<style>
 body{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;margin:0;background:#0d1117;color:#c9d1d9}
 header{padding:10px 14px;border-bottom:1px solid #21262d;display:flex;gap:18px;align-items:center}
 h1{font-size:13px;margin:0;font-weight:600;letter-spacing:.04em}
 .stat{color:#8b949e}
 table{width:100%;border-collapse:collapse}
 th{text-align:left;padding:6px 10px;color:#8b949e;font-weight:500;border-bottom:1px solid #21262d;position:sticky;top:0;background:#0d1117}
 td{padding:4px 10px;border-bottom:1px solid #161b22;white-space:nowrap}
 tr:hover td{background:#161b22}
 .n{text-align:right}
 .host{color:#58a6ff}
 .src{color:#484f58;font-size:10px}
 .org{color:#8b949e;font-size:11px}
 .own{color:#d29922;font-size:11px}
 .warn{color:#f85149;font-size:10px;border:1px solid #f85149;padding:0 3px;border-radius:3px}
 .ip{color:#6e7681}
 .q{color:#7d8590;font-size:10px;margin-top:2px;max-width:60ch;overflow:hidden;text-overflow:ellipsis}
 .closed{opacity:.45}
 img{width:14px;height:14px;vertical-align:-3px;margin-right:6px}
 img.fav{width:12px;height:12px;margin-right:5px;border-radius:2px}
</style>
<header><h1>ohmyosi</h1><span class=stat id=s>connecting...</span></header>
<table><thead><tr>
<th>process<th>proto<th>destination<th>port<th class=n>up<th class=n>down<th>state
</tr></thead><tbody id=t></tbody></table>
<script>
const flows=new Map(), procs=new Map();
let host=null, stats=null;
function fmt(n){const u=['B','K','M','G'];let i=0;while(n>=1024&&i<3){n/=1024;i++}return n.toFixed(i?1:0)+u[i]}
function render(){
  const rows=[...flows.values()].filter(f=>!f.self).sort((a,b)=>(b.bytes_up+b.bytes_down)-(a.bytes_up+a.bytes_down)).slice(0,300);
  document.getElementById('t').innerHTML=rows.map(f=>{
    const p=procs.get(f.pid);
    const icon=p&&p.icon_id?'<img src="/icons/'+p.icon_id+'.png">':'';
    const name=p?(p.app&&p.app!==p.name?p.app+' · '+p.name:p.name):(f.comm||'pid '+f.pid);
    const fav=f.remote.favicon?'<img class=fav src="/favicons/'+f.remote.favicon+'">':'';
    const own=f.remote.owner?' <span class=own>'+f.remote.owner+(f.remote.age_days>0?' · '+f.remote.age_days+'d':'')+'</span>':'';
    const org=f.remote.org?' <span class=org>'+f.remote.org+(f.remote.org_detail?' '+f.remote.org_detail:'')+'</span>':'';
    const direct=f.direct_ip?' <span class=warn>direct-ip</span>':'';
    const h=fav+(f.remote.host?'<span class=host>'+f.remote.host+'</span> <span class=src>'+(f.remote.host_src||'')+'</span>'
              :'<span class=ip>'+f.remote.ip+'</span>')+own+org+direct+(f.pre_existing&&!f.remote.host?' <span class=src>pre-existing</span>':'');
    const qs=(f.queries&&f.queries.length)?'<div class=q>resolving '+f.queries.slice(-6).join(', ')+(f.queries.length>6?' …':'')+'</div>':'';
    return '<tr class="'+(f.state==='closed'?'closed':'')+'"><td>'+icon+name+'<td>'+f.proto+'<td>'+h+qs+'<td>'+f.remote.port+
      '<td class=n>'+fmt(f.bytes_up)+'<td class=n>'+fmt(f.bytes_down)+'<td>'+f.state+'</tr>';
  }).join('');
  const pct=(a,b)=>b?Math.round(100*a/b)+'%':'—';
  document.getElementById('s').textContent=
    (host?host.hostname+' · '+host.iface+' · ':'')+
    (stats?stats.live_flows+' flows · process '+pct(stats.with_process,stats.live_flows)+
      ' · named '+pct(stats.with_name,stats.live_flows)+
      ' · org '+pct(stats.with_org,stats.live_flows)+
      ' · UNIDENTIFIED '+stats.unidentified+
      ' · direct-ip '+stats.direct_ip+
      ' · '+stats.prefixes+' prefixes · ':'')+
    procs.size+' processes';
}
const es=new EventSource('/events');
es.onmessage=e=>{
  const m=JSON.parse(e.data);
  if(m.host)host=m.host;
  if(m.stats)stats=m.stats;
  (m.procs||[]).forEach(p=>procs.set(p.pid,p));
  (m.flows||[]).forEach(f=>flows.set(f.id,f));
  (m.gone||[]).forEach(id=>flows.delete(id));
  render();
};
es.onerror=()=>{document.getElementById('s').textContent='disconnected - retrying'};
</script>`
