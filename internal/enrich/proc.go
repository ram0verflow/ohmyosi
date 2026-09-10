package enrich

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Proc is what we can learn about a process from userland alone.
type Proc struct {
	PID  int32  `json:"pid"`
	Name string `json:"name"` // the specific process: "Brave Browser Helper"
	// App is the outermost application bundle: "Brave Browser". Helper
	// processes live several bundles deep inside their parent app, so this is
	// what a user recognizes and what the UI should group by. A browser is
	// thirty processes and one icon.
	App      string `json:"app,omitempty"`
	Path     string `json:"path"` // full executable path
	BundleID string `json:"bundle_id,omitempty"`
	IconID   string `json:"icon_id,omitempty"` // served at /icons/<id>.png

	// PPID is the parent process. Lineage is half the story: a binary in /tmp is
	// one thing, the same binary launched by a shell launched by a browser is
	// another, and the parent is where that thread starts.
	PPID int32 `json:"ppid,omitempty"`

	// Signing is the code-signature verdict on the binary: "apple",
	// "developer-id", "signed", "adhoc", "unsigned" or "unknown". It speaks to
	// the software's provenance rather than the connection - the one property
	// here about what the process *is*, not who it is talking to. Ad-hoc and
	// unsigned are the interesting ones: anyone can produce them.
	Signing  string `json:"signing,omitempty"`
	SignedBy string `json:"signed_by,omitempty"` // leaf signing authority, when signed
}

// Procs resolves and caches process metadata.
//
// pktap gives us a PID and a name truncated to 16 characters, which is how you
// end up with "Google Chrome H" and no idea which of the thirty Chrome helpers
// it is. Everything readable comes from here.
type Procs struct {
	mu      sync.RWMutex
	m       map[int32]*Proc
	queued  map[int32]bool
	queue   chan int32
	iconDir string
	// Icons walks Info.plist and shells out to sips. Worth it for the demo,
	// but it is the slowest thing here, so it is optional.
	Icons bool
}

func NewProcs(iconDir string, icons bool) (*Procs, error) {
	if err := os.MkdirAll(iconDir, 0o755); err != nil {
		return nil, err
	}
	return &Procs{
		m:       make(map[int32]*Proc, 128),
		queued:  make(map[int32]bool, 32),
		queue:   make(chan int32, 128),
		iconDir: iconDir,
		Icons:   icons,
	}, nil
}

func (p *Procs) IconDir() string { return p.iconDir }

// Run starts resolver workers. Every step here shells out, so it stays well
// away from the packet path.
func (p *Procs) Run(ctx context.Context, workers int) {
	for i := 0; i < workers; i++ {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case pid := <-p.queue:
					info := p.resolve(ctx, pid)
					p.mu.Lock()
					p.m[pid] = info
					delete(p.queued, pid)
					p.mu.Unlock()
				}
			}
		}()
	}
}

// Get returns cached info, queueing a resolve on first sight. Returns nil until
// the answer is ready; the UI simply shows the kernel's truncated name until
// the real one arrives a tick later.
func (p *Procs) Get(pid int32) *Proc {
	if pid <= 0 {
		return nil
	}
	p.mu.RLock()
	info, ok := p.m[pid]
	queued := p.queued[pid]
	p.mu.RUnlock()
	if ok {
		return info
	}
	if !queued {
		p.mu.Lock()
		p.queued[pid] = true
		p.mu.Unlock()
		select {
		case p.queue <- pid:
		default:
			p.mu.Lock()
			delete(p.queued, pid)
			p.mu.Unlock()
		}
	}
	return nil
}

func (p *Procs) resolve(ctx context.Context, pid int32) *Proc {
	info := &Proc{PID: pid}
	// On macOS `ps -o comm=` usually prints the full executable path, which
	// saves a trip through libproc.
	psName, err := run(ctx, "/bin/ps", "-p", strconv.Itoa(int(pid)), "-o", "comm=")
	if err != nil || psName == "" {
		return info
	}

	// ...but not always. A process that rewrites its own title gets that title
	// back instead of a path - Electron apps do this constantly, which is why
	// Cursor's extension hosts report "Cursor Helper (Plugin): extension-host
	// empty [1-15]" and no bundle could be found for them. The title is the
	// more useful label, so keep it, and find the real binary another way.
	path := psName
	if !filepath.IsAbs(path) || !fileExists(path) {
		path = execPath(ctx, pid)
		info.Name = psName
	}
	if path == "" {
		return info
	}
	info.Path = path
	if info.Name == "" {
		info.Name = filepath.Base(path)
	}
	info.PPID = parentPID(ctx, pid)
	info.Signing, info.SignedBy = codeSignature(ctx, path)

	bundles := appBundles(path)
	if len(bundles) == 0 {
		return info
	}
	inner, outer := bundles[0], bundles[len(bundles)-1]

	// CFBundleName is often absent or unhelpfully abbreviated; the bundle
	// directory name is what the user sees in Finder. A self-assigned process
	// title beats both, so it wins if we have one.
	if psName == filepath.Base(path) || filepath.IsAbs(psName) {
		info.Name = strings.TrimSuffix(filepath.Base(inner), ".app")
	}
	info.App = strings.TrimSuffix(filepath.Base(outer), ".app")
	if v := plistValue(ctx, filepath.Join(inner, "Contents", "Info.plist"), "CFBundleIdentifier"); v != "" {
		info.BundleID = v
	}
	if p.Icons {
		// Try the outermost bundle first. Helper bundles ship no artwork of
		// their own, which is why every browser process showed up iconless
		// while standalone apps were fine.
		for i := len(bundles) - 1; i >= 0; i-- {
			if id := p.icon(ctx, bundles[i]); id != "" {
				info.IconID = id
				break
			}
		}
	}
	return info
}

// appBundles returns every .app ancestor of an executable, innermost first.
//
// A browser helper is buried several bundles deep:
//
//	Brave Browser.app/Contents/Frameworks/Brave Browser Framework.framework/
//	  Versions/X/Helpers/Brave Browser Helper.app/Contents/MacOS/...
//
// The innermost bundle names the specific process; the outermost is the
// application a person would recognize, and the only one with an icon.
func appBundles(exe string) []string {
	var out []string
	dir := exe
	for i := 0; i < 24; i++ {
		dir = filepath.Dir(dir)
		if dir == "/" || dir == "." {
			break
		}
		if strings.HasSuffix(dir, ".app") {
			out = append(out, dir)
		}
	}
	return out
}

func plistValue(ctx context.Context, plist, key string) string {
	out, err := run(ctx, "/usr/bin/plutil", "-extract", key, "raw", "-o", "-", plist)
	if err != nil {
		return ""
	}
	return out
}

// icon renders a bundle's icon to a PNG in the cache and returns its id.
// Failures are silent: a missing icon is cosmetic.
func (p *Procs) icon(ctx context.Context, app string) string {
	sum := sha1.Sum([]byte(app))
	id := hex.EncodeToString(sum[:])[:16]
	dst := filepath.Join(p.iconDir, id+".png")
	if st, err := os.Stat(dst); err == nil {
		if st.Size() > 0 {
			return id
		}
		os.Remove(dst) // a previous attempt failed halfway
	}

	if icns := findICNS(ctx, app); icns != "" {
		if _, err := run(ctx, "/usr/bin/sips", "-s", "format", "png", "-Z", "64", icns, "--out", dst); err == nil {
			return id
		}
	}
	// No .icns: modern apps ship artwork in Assets.car, which needs a real
	// asset-catalog parser. QuickLook already has one, so let it render the
	// thumbnail rather than reimplementing Apple's format.
	if quickLookIcon(ctx, app, dst) {
		return id
	}
	return ""
}

func findICNS(ctx context.Context, app string) string {
	res := filepath.Join(app, "Contents", "Resources")
	if v := plistValue(ctx, filepath.Join(app, "Contents", "Info.plist"), "CFBundleIconFile"); v != "" {
		if !strings.HasSuffix(v, ".icns") {
			v += ".icns"
		}
		if cand := filepath.Join(res, v); fileExists(cand) {
			return cand
		}
	}
	if m, _ := filepath.Glob(filepath.Join(res, "*.icns")); len(m) > 0 {
		return m[0]
	}
	return ""
}

// quickLookIcon renders via qlmanage, which writes <name>.png into a directory
// of its choosing, so we render to a scratch dir and move the result.
func quickLookIcon(ctx context.Context, app, dst string) bool {
	tmp, err := os.MkdirTemp("", "ohmyosi-ql")
	if err != nil {
		return false
	}
	defer os.RemoveAll(tmp)
	if _, err := run(ctx, "/usr/bin/qlmanage", "-t", "-s", "128", "-o", tmp, app); err != nil {
		return false
	}
	m, _ := filepath.Glob(filepath.Join(tmp, "*.png"))
	if len(m) == 0 {
		return false
	}
	in, err := os.ReadFile(m[0])
	if err != nil || len(in) == 0 {
		return false
	}
	return os.WriteFile(dst, in, 0o644) == nil
}

// execPath finds a process's real binary when its reported name is a rewritten
// title rather than a path. lsof's "txt" descriptors are the mapped executable
// images; the first is the binary itself. libproc's proc_pidpath would be
// cheaper but needs cgo, and avoiding cgo is worth one exec here.
func execPath(ctx context.Context, pid int32) string {
	out, err := run(ctx, "/usr/sbin/lsof", "-p", strconv.Itoa(int(pid)), "-a", "-d", "txt", "-Fn")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "n/") {
			return line[1:]
		}
	}
	return ""
}

// parentPID reads a process's parent from ps. Zero on any failure - lineage is
// useful, not load-bearing.
func parentPID(ctx context.Context, pid int32) int32 {
	out, err := run(ctx, "/bin/ps", "-p", strconv.Itoa(int(pid)), "-o", "ppid=")
	if err != nil {
		return 0
	}
	if n, err := strconv.Atoi(strings.TrimSpace(out)); err == nil {
		return int32(n)
	}
	return 0
}

// codeSignature asks codesign what signed a binary, and maps its answer to a
// small vocabulary the scorer and the UI can both use.
//
// codesign writes its detail to stderr, so combined output is read. The verdict
// is deliberately coarse: the distinction that matters is between code whose
// origin is attestable (Apple, a Developer ID certificate) and code where it is
// not (ad-hoc, unsigned). The latter proves nothing about where it came from,
// which is exactly what makes an unnamed connection from it worth a look.
func codeSignature(ctx context.Context, path string) (status, authority string) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(cctx, "/usr/bin/codesign", "-dv", "--verbose=2", path).CombinedOutput()
	s := string(out)
	switch {
	case strings.Contains(s, "code object is not signed at all"):
		return "unsigned", ""
	case strings.Contains(s, "Signature=adhoc"):
		return "adhoc", ""
	}
	// Authority lines run most-specific first; the leaf certificate is the one
	// that names who signed it.
	var auth string
	for _, line := range strings.Split(s, "\n") {
		if a, ok := strings.CutPrefix(line, "Authority="); ok {
			auth = strings.TrimSpace(a)
			break
		}
	}
	switch {
	case auth == "":
		return "unknown", ""
	case strings.HasPrefix(auth, "Software Signing"), strings.Contains(auth, "Apple"):
		return "apple", auth
	case strings.HasPrefix(auth, "Developer ID"):
		return "developer-id", auth
	default:
		return "signed", auth
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func run(ctx context.Context, bin string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, args...).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
