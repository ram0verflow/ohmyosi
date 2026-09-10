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

// DisplayPID returns the process the UI should show for this flow.
func (f Flow) DisplayPID() int32 {
	if f.EPID > 0 && IsSystemResolver(f.Comm) {
		return f.EPID
	}
	return f.PID
}

// DisplayComm returns the comm matching DisplayPID.
func (f Flow) DisplayComm() string {
	if f.EPID > 0 && IsSystemResolver(f.Comm) && f.EComm != "" {
		return f.EComm
	}
	return f.Comm
}
