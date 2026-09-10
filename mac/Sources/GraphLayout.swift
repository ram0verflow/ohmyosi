import Foundation
import CoreGraphics
import SwiftUI

/// Layout: sector fans, not concentric rings.
///
/// The previous version put every process on one ring and every destination on
/// another, both starting at the same angle, then drew a cable from the centre
/// to a process **once per link**. With fifteen apps and a hundred links that
/// is a hundred stacked cables leaving the middle and a hundred more crossing
/// the whole canvas to reach a destination on the far side. That is the ball of
/// wool, and no amount of colour or easing fixes it - it is a layout problem.
///
/// The fix is to give each application its own angular sector and place its
/// destinations directly outside it. Cables become short and roughly radial,
/// they stop crossing the centre, and the picture reads as "this app talks to
/// these places" at a glance, which is the entire point.
/// Stable angular slots.
///
/// `build` runs on every frame against whatever flows are live at that instant.
/// With sectors derived from the current app list, one process finishing a
/// connection renumbers every sector and the entire ring slides - which is
/// invisible in a screenshot and unusable in motion. Watching it for ten
/// seconds, the app count went 13 to 12 to 11 and nothing stayed where it was.
///
/// So position is assigned once, on first sight, and kept. An app that goes
/// quiet holds its slot for a while before releasing it, because closing the
/// gap immediately is just as disruptive as opening one.
@MainActor
enum LayoutSlots {
    private static var order: [String] = []
    private static var lastSeen: [String: Date] = [:]

    /// How long a departed app keeps its place. Long enough to cover a process
    /// that reconnects every few seconds, short enough that a closed app is
    /// eventually reclaimed.
    static let holdSeconds: TimeInterval = 45

    /// Stable placement for one app's destinations.
    ///
    /// Which destinations are *shown* is chosen by traffic, which is right.
    /// Where they are *drawn* must not be, or every tick reorders the fan and
    /// the icons swap places under the cursor. Membership can change; position
    /// should not.
    private static var destOrder: [String: [String]] = [:]

    static func placeDestinations(app: String, shown: [String]) -> [String] {
        var order = destOrder[app] ?? []
        for key in shown where !order.contains(key) { order.append(key) }
        // Forget anything that has dropped out of the shown set entirely, so
        // the list cannot grow without bound.
        let shownSet = Set(shown)
        order.removeAll { !shownSet.contains($0) }
        destOrder[app] = order
        return order
    }

    static func ringOrder(active: [String], limit: Int) -> [String] {
        let now = Date()
        for key in active {
            lastSeen[key] = now
            if !order.contains(key) { order.append(key) }
        }
        order.removeAll { key in
            guard let seen = lastSeen[key] else { return true }
            return now.timeIntervalSince(seen) > holdSeconds
        }
        // Bounded. `active` arrives sorted by traffic, so when the ring is full
        // a newcomer only takes a slot from something that has actually gone
        // quiet - never from a live app, which would make positions jump.
        if order.count > limit {
            let liveSet = Set(active)
            let stale = order.filter { !liveSet.contains($0) }
            for key in stale where order.count > limit {
                order.removeAll { $0 == key }
            }
            if order.count > limit { order = Array(order.prefix(limit)) }
        }
        return order
    }
}

@MainActor
enum GraphLayout {
    nonisolated static let daemonBase = URL(string: "http://127.0.0.1:7777")!

    /// Destinations shown per application before the tail is folded into a
    /// single "+N more" node. A browser with sixty hosts is a scroll bar, not
    /// a diagram; the top few plus an honest count is more informative.
    static let destinationsPerApp = 6

    /// Sectors on the ring. Past this the wedges are too narrow to label, and
    /// the quiet tail is better represented honestly as one node than as a
    /// dozen slivers nobody can read.
    static let maxSectors = 12

    static func build(
        flows: [Flow],
        processes: [Int32: ProcessInfo],
        hostname: String,
        viewport: CGSize
    ) -> GraphScene {
        let links = GraphReducer.reduce(flows, processes: processes)
        let live = groupByApp(links)
        // Walk the stable order, not the live list. Slots held for a departed
        // app stay empty rather than letting its neighbours slide across.
        // Which apps and destinations moved a packet recently. Everything else
        // is drawn as an open-but-quiet connection rather than hidden.
        let now = Date().timeIntervalSince1970
        var liveApps = Set<String>()
        var liveGroups = Set<String>()
        for f in GraphReducer.prepare(flows, processes: processes) where f.isLive(now: now) {
            liveApps.insert(GraphReducer.processName(for: f, processes: processes))
            let label = GraphReducer.destinationLabel(for: f)
            liveGroups.insert(registrable(label) ?? label)
        }

        let byKey = Dictionary(uniqueKeysWithValues: live.map { ($0.key, $0) })
        let ring = LayoutSlots.ringOrder(active: live.map(\.key), limit: maxSectors)
        let apps = ring.compactMap { byKey[$0] }
        guard !apps.isEmpty else {
            return GraphScene(
                nodes: [machineNode(hostname: hostname, at: CGPoint(x: viewport.width / 2, y: viewport.height / 2))],
                edges: [],
                canvasSize: viewport
            )
        }

        // Geometry. The canvas is sized from the number of sectors, not from
        // the number of destinations, so it stays a readable size instead of
        // ballooning to 2800 points and shrinking every node to a speck.
        // Fixed geometry, deliberately. Deriving the radius from the slot
        // count made the canvas grow to several thousand points, and made it
        // RESIZE whenever an app appeared - which changes the zoom level on its
        // own, since the viewport scales relative to canvas fit. Density is the
        // sector angle's job; the circle stays the same size.
        // Roomier: icons were touching their neighbours' labels.
        let procRadius: CGFloat = 300
        let destRadius: CGFloat = 580
        let laneOffset: CGFloat = 112
        let canvasW: CGFloat = 1560
        let canvasH: CGFloat = 1560
        let centre = CGPoint(x: canvasW / 2, y: canvasH / 2)

        // Cables leave the machine's edge, not its centre point.
        let machineRim: CGFloat = 140
        let maxAppBytes = apps.map(\.bytes).max() ?? 1
        let maxDestBytes = apps.flatMap { $0.destinations.map(\.bytes) }.max() ?? 1

        var nodes: [GraphNode] = [machineNode(hostname: hostname, at: centre)]
        var edges: [GraphEdge] = []

        // Sector width is proportional to how many destinations an app has, so
        // a busy browser gets room and a daemon with one endpoint does not.
        // Square-rooted so a browser with thirty destinations gets more room
        // than a daemon with one, but not thirty times more - linear weighting
        // handed half the circle to Brave and crushed everything else together.
        // Square-rooting flattened this too far: a browser with eight
        // destinations got barely twice the wedge of a daemon with one, and its
        // labels stacked. Linear-with-a-floor-and-a-cap gives the busy app
        // roughly four times the room without letting it take the whole circle.
        let weightOf: (App) -> Double = { app in
            1.0 + Double(min(app.destinations.count, destinationsPerApp + 1)) * 0.6
        }
        // Absent-but-held slots weigh a constant, so the ring keeps its shape
        // while an app is away and it lands back in the same place.
        let heldWeight = 1.0
        let totalWeight = ring.reduce(0.0) { sum, key in
            sum + (byKey[key].map(weightOf) ?? heldWeight)
        }
        var cursor = -Double.pi / 2 - .pi / Double(max(ring.count, 1))

        for (index, key) in ring.enumerated() {
            guard let app = byKey[key] else {
                cursor += 2 * Double.pi * heldWeight / totalWeight
                continue
            }
            let sector = 2 * Double.pi * weightOf(app) / totalWeight
            let mid = cursor + sector / 2
            let seed = GraphReducer.stableHue(app.key)

            let procSize = Theme.nodeSize(bytes: app.bytes, maxBytes: maxAppBytes, base: 54, spread: 24)
            let procPoint = CGPoint(x: centre.x + cos(mid) * procRadius, y: centre.y + sin(mid) * procRadius)
            let procID = "p:\(app.key)"
            nodes.append(GraphNode(
                id: procID, kind: .process, title: app.label, subtitle: nil,
                x: procPoint.x, y: procPoint.y, size: procSize,
                iconURL: app.iconURL, localIconPath: app.localPath,
                accentHue: seed, bytes: app.bytes
            ))

            // One cable from the machine per application. Previously this was
            // emitted once per link, which is what produced the dense grey
            // bundle in the middle of the old render.
            let rim = CGPoint(
                x: centre.x + cos(mid) * machineRim,
                y: centre.y + sin(mid) * machineRim
            )
            let appLive = liveApps.contains(app.key)
            edges.append(GraphEdge(
                id: "hub:\(app.key)", from: "mac", to: procID, bytes: app.bytes,
                colorStart: appLive ? Theme.accent(seed) : Theme.idleWire,
                colorEnd: appLive ? Theme.accent(seed) : Theme.idleWire,
                routePoints: radialCurve(from: rim, to: procPoint, bow: 0.08),
                laneIndex: index, stagger: Double(index) * 0.05, style: .hub,
                isActive: appLive
            ))

            // Pick by traffic, place by stable order.
            let picked = Array(app.destinations.prefix(destinationsPerApp))
            let hidden = app.destinations.dropFirst(destinationsPerApp)
            let placement = LayoutSlots.placeDestinations(app: app.key, shown: picked.map(\.key))
            let byDestKey = Dictionary(uniqueKeysWithValues: picked.map { ($0.key, $0) })
            let shown = placement.compactMap { byDestKey[$0] }
            var slots = shown.count + (hidden.isEmpty ? 0 : 1)
            slots = max(slots, 1)

            // Fan the destinations across the sector, inset from its edges so
            // neighbouring apps stay visually separate.
            let inset = sector * 0.20
            let span = max(sector - inset * 2, 0.0001)
            for (j, dest) in shown.enumerated() {
                let t = slots == 1 ? 0.5 : Double(j) / Double(slots - 1)
                let a = cursor + inset + span * t
                let size = Theme.nodeSize(bytes: dest.bytes, maxBytes: maxDestBytes, base: 40, spread: 16)
                // Two lanes. Neighbours in a fan land at different radii so
                // their labels interleave rather than stack on each other.
                let lane = j % 2 == 0 ? destRadius : destRadius + laneOffset
                let point = CGPoint(x: centre.x + cos(a) * lane, y: centre.y + sin(a) * lane)
                nodes.append(GraphNode(
                    id: "\(procID)>\(dest.key)", kind: .destination,
                    title: dest.label, subtitle: dest.subtitle,
                    x: point.x, y: point.y, size: size,
                    iconURL: dest.iconURL, localIconPath: nil,
                    accentHue: seed, bytes: dest.bytes
                ))
                let destLive = liveGroups.contains(dest.key)
                edges.append(GraphEdge(
                    id: "l:\(procID)>\(dest.key)", from: procID, to: "\(procID)>\(dest.key)",
                    bytes: dest.bytes,
                    colorStart: destLive ? Theme.accent(seed) : Theme.idleWire,
                    colorEnd: destLive ? Theme.destinationTint(seed) : Theme.idleWire,
                    routePoints: radialCurve(from: procPoint, to: point, bow: 0.16),
                    laneIndex: index * 100 + j, stagger: Double(index) * 0.05 + Double(j) * 0.03,
                    style: .link, isActive: destLive
                ))
            }

            if !hidden.isEmpty {
                let a = cursor + inset + span
                let bytes = hidden.reduce(UInt64(0)) { $0 + $1.bytes }
                let lane = shown.count % 2 == 0 ? destRadius : destRadius + laneOffset
                let point = CGPoint(x: centre.x + cos(a) * lane, y: centre.y + sin(a) * lane)
                let id = "\(procID)>+more"
                nodes.append(GraphNode(
                    id: id, kind: .intermediate,
                    title: "+\(hidden.count) more", subtitle: "smaller destinations",
                    x: point.x, y: point.y, size: 30,
                    iconURL: nil, localIconPath: nil, accentHue: seed, bytes: bytes
                ))
                edges.append(GraphEdge(
                    id: "l:\(id)", from: procID, to: id, bytes: bytes,
                    colorStart: Theme.idleWire, colorEnd: Theme.idleWire,
                    routePoints: radialCurve(from: procPoint, to: point, bow: 0.16),
                    laneIndex: index * 100 + 99, stagger: Double(index) * 0.05,
                    style: .relay, isActive: false
                ))
            }

            cursor += sector
        }

        return GraphScene(nodes: nodes, edges: edges, canvasSize: CGSize(width: canvasW, height: canvasH))
    }

    // MARK: - Grouping

    struct Destination {
        let key: String
        let label: String
        let subtitle: String?
        let iconURL: URL?
        var bytes: UInt64
    }

    struct App {
        let key: String
        let label: String
        let iconURL: URL?
        let localPath: String?
        var bytes: UInt64
        var destinations: [Destination]
    }

    /// Collapses links into one entry per application, with its destinations
    /// merged by registrable domain. Merging is what takes a browser from
    /// thirty nodes to six: api2.cursor.sh and agentn.global.api5.cursor.sh are
    /// one place as far as a person is concerned.
    private static func groupByApp(_ links: [ForensicMap.Link]) -> [App] {
        var byApp: [String: App] = [:]
        var destsByApp: [String: [String: Destination]] = [:]

        for link in links {
            let group = groupKey(for: link)
            var app = byApp[link.processKey] ?? App(
                key: link.processKey, label: link.processLabel,
                iconURL: link.iconURL, localPath: link.localPath,
                bytes: 0, destinations: []
            )
            app.bytes += link.bytes
            byApp[link.processKey] = app

            var dests = destsByApp[link.processKey] ?? [:]
            if var existing = dests[group] {
                existing.bytes += link.bytes
                dests[group] = existing
            } else {
                dests[group] = Destination(
                    key: group,
                    label: group,
                    subtitle: link.destinationSubtitle,
                    iconURL: link.destinationIconURL,
                    bytes: link.bytes
                )
            }
            destsByApp[link.processKey] = dests
        }

        return byApp.values.map { app in
            var copy = app
            copy.destinations = (destsByApp[app.key] ?? [:]).values.sorted { $0.bytes > $1.bytes }
            return copy
        }
        .sorted { $0.bytes > $1.bytes }
    }

    /// The label a person should read, and the key destinations merge on.
    ///
    /// The reducer namespaces its keys ("d:1.2.3.4"), which is correct for a key
    /// and wrong for a label - those prefixes were being rendered verbatim on
    /// the canvas. Prefer the registrable domain, fall back to the label, and
    /// only ever fall back to the key with its namespace stripped.
    private static func groupKey(for link: ForensicMap.Link) -> String {
        if let d = registrable(link.destinationLabel), !d.isEmpty { return d }
        let label = link.destinationLabel.trimmingCharacters(in: .whitespaces)
        if !label.isEmpty { return label }
        let key = link.destinationKey
        for prefix in ["d:", "i:", "p:"] where key.hasPrefix(prefix) {
            return String(key.dropFirst(prefix.count))
        }
        return key
    }

    /// Registrable domain, near enough. The daemon does this properly with the
    /// Public Suffix List; here we only need enough to group a fan, so a short
    /// list of common multi-part suffixes covers it. Anything that is not a
    /// hostname (an address, a label like "AS13335") is passed through.
    nonisolated static let multiPartSuffixes: Set<String> = [
        "co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "co.in", "co.nz", "co.za",
        "com.au", "com.br", "com.cn", "com.mx", "com.tr", "com.sg", "com.hk",
    ]

    nonisolated static func registrable(_ host: String) -> String? {
        let h = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: ". "))
        guard !h.isEmpty, h.contains("."), !h.contains(":"), !h.contains("/") else { return nil }
        // An IPv4 literal has no registrable domain.
        if h.allSatisfy({ $0.isNumber || $0 == "." }) { return nil }
        let parts = h.split(separator: ".").map(String.init)
        guard parts.count >= 2 else { return nil }
        let lastTwo = parts.suffix(2).joined(separator: ".")
        if multiPartSuffixes.contains(lastTwo), parts.count >= 3 {
            return parts.suffix(3).joined(separator: ".")
        }
        return lastTwo
    }

    // MARK: - Geometry

    private static func machineNode(hostname: String, at p: CGPoint) -> GraphNode {
        GraphNode(
            id: "mac", kind: .machine, title: hostname, subtitle: nil,
            x: p.x, y: p.y, size: 260, iconURL: nil, localIconPath: nil,
            accentHue: 0, bytes: 0
        )
    }

    /// A gently bowed cubic between two points. The bow is perpendicular and
    /// small - enough to separate parallel cables, not enough to send one
    /// looping over the top of the canvas the way the old router did.
    private static func radialCurve(from a: CGPoint, to b: CGPoint, bow: CGFloat) -> [CGPoint] {
        let dx = b.x - a.x
        let dy = b.y - a.y
        let nx = -dy * bow
        let ny = dx * bow
        return [
            a,
            CGPoint(x: a.x + dx * 0.33 + nx * 0.5, y: a.y + dy * 0.33 + ny * 0.5),
            CGPoint(x: a.x + dx * 0.67 + nx * 0.5, y: a.y + dy * 0.67 + ny * 0.5),
            b,
        ]
    }

    // MARK: - Selection

    static func flows(matching node: GraphNode, in flows: [Flow], processes: [Int32: ProcessInfo]) -> [Flow] {
        let clean = GraphReducer.prepare(flows, processes: processes)
        switch node.kind {
        case .machine:
            return clean
        case .process:
            let name = String(node.id.dropFirst(2))
            return clean.filter { GraphReducer.processName(for: $0, processes: processes) == name }
        case .destination, .intermediate:
            // Node ids are "p:<app>><group>", so both halves are recoverable.
            let parts = node.id.components(separatedBy: ">")
            guard let appPart = parts.first, appPart.hasPrefix("p:") else { return [] }
            let app = String(appPart.dropFirst(2))
            let group = parts.count > 1 ? parts[1] : ""
            return clean.filter { flow in
                guard GraphReducer.processName(for: flow, processes: processes) == app else { return false }
                if group == "+more" { return true }
                let label = GraphReducer.destinationLabel(for: flow)
                return registrable(label) == group || label == group
            }
        }
    }
}
