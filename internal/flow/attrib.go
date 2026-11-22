package flow

import "strings"

// IsSystemResolver reports processes that resolve on behalf of others.
// Their socket PID is misleading; pktap's effective PID is the real client.
func IsSystemResolver(comm string) bool {
	comm = strings.TrimSpace(comm)
	switch comm {
	case "mDNSResponder", "configd", "named", "systemd-resolved", "unbound":
		return true
	}
	return strings.HasPrefix(comm, "mDNSResponder")
}

// useEffective: show the effective process when the socket owner is a resolver
// acting for someone else, or when pktap gave no owner at all (it stamps some
// Chrome connections "proc 0" with Chrome only as the effective process).
func (f Flow) useEffective() bool {
	return f.EPID > 0 && (f.PID <= 0 || IsSystemResolver(f.Comm))
}

// DisplayPID returns the process the UI should show for this flow.
func (f Flow) DisplayPID() int32 {
	if f.useEffective() {
		return f.EPID
	}
	return f.PID
}

// DisplayComm returns the comm matching DisplayPID.
func (f Flow) DisplayComm() string {
	if f.useEffective() && f.EComm != "" {
		return f.EComm
	}
	return f.Comm
}
