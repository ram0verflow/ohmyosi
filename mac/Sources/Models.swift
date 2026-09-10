import Foundation

struct Envelope: Codable, Sendable {
    let type: String
    let t: Double
    var host: HostInfo?
    var procs: [ProcessInfo]?
    var flows: [Flow]?
    var gone: [String]?
    var stats: Stats?
    var alerts: [Alert]?
}

/// One moment the daemon judged worth interrupting for: a flow crossing into a
/// loud band, or a genuinely new process/destination pair. It carries its own
/// reasons, because an alert you cannot argue with is one you cannot trust.
struct Alert: Codable, Sendable, Identifiable, Hashable {
    let flow_id: String
    let comm: String
    let dest: String
    let score: Int
    let band: String
    var reasons: [String]?
    let t: Double

    var id: String { "\(flow_id)-\(t)" }
}

struct HostInfo: Codable, Sendable {
    let hostname: String
    let iface: String
    let pktap: Bool
    let started: Double
    let version: String
}

struct Endpoint: Codable, Sendable, Hashable {
    let ip: String
    let port: UInt16
    var host: String?
    var host_src: String?
    var org: String?
    var org_detail: String?
    var org_src: String?
    var domain: String?
    var owner: String?
    var registrar: String?
    var age_days: Int?
    var favicon: String?
    var asn: UInt32?
    var asn_org: String?
    var country: String?
    var trail: [String]?

    var displayName: String {
        if let h = host, ForensicMap.isIntentHost(h, src: host_src) {
            return h
        }
        if let d = domain, !d.isEmpty, !ForensicMap.isInfrastructureHost(d) { return d }
        if let org, ForensicMap.isInfrastructureOrg(org) { /* skip as primary */ }
        if let org, !org.isEmpty, GraphReducer.isReadableOrg(org), !ForensicMap.isInfrastructureOrg(org) { return org }
        if let asn_org, GraphReducer.isReadableOrg(asn_org), !ForensicMap.isInfrastructureOrg(asn_org) { return asn_org }
        if let asn, asn > 0 { return "AS\(asn)" }
        return ip
    }

    var subtitle: String? {
        if let host, !host.isEmpty, let org, !org.isEmpty, host != org { return org }
        return org_detail
    }
}

struct Flow: Codable, Sendable, Identifiable, Hashable {
    let id: String
    let proto: String
    let pid: Int32
    let comm: String
    var iface: String?
    let local: Endpoint
    let remote: Endpoint
    let bytes_up: UInt64
    let bytes_down: UInt64
    var pkts_up: UInt64?
    var pkts_down: UInt64?
    let first_seen: Double
    let last_seen: Double
    let state: String
    var isSelf: Bool?
    var pre_existing: Bool?
    var direct_ip: Bool?
    var queries: [String]?
    // The suspicion score, its band, and the sentences behind it. Never a bare
    // number: the reasons are the point, and the UI shows them.
    var suspicion: Int?
    var suspicion_band: String?
    var reasons: [String]?
    // The TLS client fingerprint of whatever opened this flow. Identifies the
    // software, survives ECH, and is the odd-one-out signal when everything
    // else about the far end is hidden.
    var ja4: String?
    // True the first time this process is seen reaching this destination.
    var first_contact: Bool?
    // A rule denies this flow. Enforced says whether it was actually applied
    // (pf/hosts) or is only what the rule would do, when enforcement is off.
    var blocked: Bool?
    var enforced: Bool?
    var rule: String?

    var totalBytes: UInt64 { bytes_up + bytes_down }
    var suspicionScore: Int { suspicion ?? 0 }
    var band: SuspicionBand { SuspicionBand(rawValue: suspicion_band ?? "") ?? .quiet }

    /// Moved a packet recently. The daemon only re-sends a flow when it
    /// changes, so last_seen is exactly "when did traffic last cross this".
    func isLive(now: Double, within: Double = 3.0) -> Bool {
        now - last_seen < within
    }

    enum CodingKeys: String, CodingKey {
        case id, proto, pid, comm, iface, local, remote
        case bytes_up, bytes_down, pkts_up, pkts_down
        case first_seen, last_seen, state
        case isSelf = "self"
        case pre_existing, direct_ip, queries
        case suspicion, suspicion_band, reasons, ja4, first_contact
        case blocked, enforced, rule
    }
}

/// How loudly a flow is asking for attention. Ordered so `>` means "more
/// suspicious", which the triage list and node rings both rely on.
enum SuspicionBand: String, Comparable, Sendable {
    case quiet, notable, unusual, loud

    private var rank: Int {
        switch self {
        case .quiet: return 0
        case .notable: return 1
        case .unusual: return 2
        case .loud: return 3
        }
    }

    static func < (a: SuspicionBand, b: SuspicionBand) -> Bool { a.rank < b.rank }

    /// Whether this band is worth surfacing on its own. Quiet and notable are
    /// the ordinary texture of a busy machine; unusual and loud are not.
    var wantsAttention: Bool { self >= .unusual }
}

/// A block/allow rule, mirroring internal/rules.Rule on the daemon.
struct BlockRule: Codable, Sendable, Identifiable, Hashable {
    let id: String
    var scope: String   // app | domain | dest | port
    var match: String
    var action: String  // block | allow
    var note: String?
    var enabled: Bool
    var created: Int?

    var isBlock: Bool { action != "allow" }
}

/// One destination seen this session, whether or not it is still live. This is
/// what the "all sites" view is built from: the honest answer to "everything my
/// machine talked to", not just what happens to be moving a packet right now.
struct DestinationSeen: Identifiable, Sendable, Hashable {
    let id: String        // stable key: domain, host, or ip
    var name: String
    var org: String?
    var lastApp: String
    var bytes: UInt64
    var lastSeen: Double
    var firstSeen: Double
    var band: SuspicionBand
    var blocked: Bool

    func isLive(now: Double) -> Bool { now - lastSeen < 5 }
}

struct ProcessInfo: Codable, Sendable, Identifiable, Hashable {
    var id: Int32 { pid }
    let pid: Int32
    let name: String
    var app: String?
    var path: String?
    var bundle_id: String?
    var icon_id: String?
    var ppid: Int32?
    // Code-signature verdict: apple | developer-id | signed | adhoc | unsigned
    // | unknown. It speaks to what the software is, not who it talks to.
    var signing: String?
    var signed_by: String?

    var displayName: String { app ?? name }

    /// The provenance of the binary is not attestable: ad-hoc or unsigned code
    /// anyone could have produced. Worth a badge next to a connection.
    var untrustedSignature: Bool { signing == "adhoc" || signing == "unsigned" }
}

struct Stats: Codable, Sendable {
    var packets: UInt64?
    var decoded: UInt64?
    var undecoded: UInt64?
    var flows: Int?
    var procs_known: Int?
    var live_flows: Int?
    var with_process: Int?
    var with_name: Int?
    var with_org: Int?
    var unidentified: Int?
    var direct_ip: Int?
    var prefixes: Int?
}

import Foundation
import CoreGraphics
import SwiftUI

enum GraphNodeKind: Sendable {
    case machine, process, intermediate, destination
}

struct GraphNode: Identifiable, Sendable {
    let id: String
    let kind: GraphNodeKind
    let title: String
    let subtitle: String?
    let x: CGFloat
    let y: CGFloat
    let size: CGFloat
    let iconURL: URL?
    let localIconPath: String?
    let accentHue: Double
    let bytes: UInt64
    /// The highest score among the flows this node stands for, and its band.
    /// Worst-case rather than average on purpose: one loud connection inside a
    /// quiet app is exactly what must not be averaged away.
    var suspicion: Int = 0
    var suspicionBand: String = "quiet"
}

struct GraphEdge: Identifiable, Sendable {
    enum Style: Sendable { case hub, relay, link }

    let id: String
    let from: String
    let to: String
    var bytes: UInt64
    let colorStart: Color
    let colorEnd: Color
    let routePoints: [CGPoint]
    let laneIndex: Int
    let stagger: Double
    var style: Style = .link
    /// Traffic crossed this in the last few seconds. Drives whether the cable
    /// is lit and carrying particles, or greyed out and still.
    var isActive: Bool = true
}
