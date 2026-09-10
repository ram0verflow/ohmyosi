import Foundation

enum GraphReducer {
    // Low on purpose. A connection that is open but idle still belongs on the
    // canvas; filtering by volume hid exactly the sockets worth knowing about.
    static let minBytes: UInt64 = 0
    static let minBytesDefault: UInt64 = 128

    private static let systemProcesses: Set<String> = [
        "mDNSResponder", "apsd", "configd", "kernel_task", "launchd",
        "symptomsd", "trustd", "nsurlsessiond", "cfprefsd", "distnoted",
        "WindowServer", "loginwindow", "UserEventAgent", "coreaudiod",
    ]

    static func isBrowser(_ name: String) -> Bool {
        let n = name.lowercased()
        return n.contains("brave") || n.contains("chrome") || n.contains("firefox")
            || n.contains("safari") || n.contains("arc") || n.contains("edge")
    }

    static func prepare(_ flows: [Flow], processes: [Int32: ProcessInfo]) -> [Flow] {
        flows.filter { flow in
            if flow.isSelf == true { return false }
            let proc = processName(for: flow, processes: processes)
            let floor = isBrowser(proc) ? minBytes : minBytesDefault
            if flow.totalBytes < floor { return false }
            let ip = flow.remote.ip
            if ip.hasPrefix("127.") || ip == "::1" { return false }
            if systemProcesses.contains(proc) { return false }
            if flow.remote.port == 53 && flow.remote.host_src == "rdns" && (flow.queries ?? []).isEmpty {
                return false
            }
            return true
        }
    }

    static func destinationLabel(for flow: Flow) -> String {
        let proc = processName(for: flow, processes: [:])
        return ForensicMap.finalDestination(for: flow, browser: isBrowser(proc))?.label ?? flow.remote.ip
    }

    static func destinationKey(for flow: Flow) -> String {
        let proc = processName(for: flow, processes: [:])
        return ForensicMap.finalDestination(for: flow, browser: isBrowser(proc))?.key ?? flow.remote.ip
    }

    static func processName(for flow: Flow, processes: [Int32: ProcessInfo]) -> String {
        let raw = processes[flow.pid]?.app ?? processes[flow.pid]?.name ?? flow.comm
        if raw.contains("Helper") {
            return processes[flow.pid]?.app ?? raw.replacingOccurrences(
                of: " Helper.*", with: "", options: .regularExpression
            )
        }
        return raw
    }

    /// All forensic links — no artificial cap; browsers keep every tab/host.
    static func reduce(_ flows: [Flow], processes: [Int32: ProcessInfo]) -> [ForensicMap.Link] {
        let clean = prepare(flows, processes: processes)
        let expanded = ForensicMap.expand(clean, processes: processes, daemonBase: GraphLayout.daemonBase)

        var merged: [String: ForensicMap.Link] = [:]
        for link in expanded {
            let key = "\(link.processKey)|\(link.intermediateKey ?? "")|\(link.destinationKey)"
            if let existing = merged[key] {
                merged[key] = existing.addingBytes(link.bytes)
            } else {
                merged[key] = link
            }
        }
        return merged.values.sorted { $0.bytes > $1.bytes }
    }

    static func isReadableOrg(_ s: String) -> Bool {
        !looksLikeDate(s) && s.count > 2 && !s.allSatisfy { $0.isNumber || $0 == "." || $0 == "-" }
    }

    static func looksLikeDate(_ s: String) -> Bool {
        s.range(of: #"^\d{4}-\d{2}-\d{2}$"#, options: .regularExpression) != nil
    }

    static func stableHue(_ s: String) -> Double {
        var hash: UInt64 = 5381
        for c in s.utf8 { hash = ((hash << 5) &+ hash) &+ UInt64(c) }
        return Double(hash % 360) / 360.0
    }
}
