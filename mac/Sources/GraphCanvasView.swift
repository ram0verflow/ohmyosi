import SwiftUI

/// The canvas.
///
/// Three things separate this from a diagram that happens to move:
///
///   - **Focus.** Clicking an app dims everything that is not its fan. On a
///     hundred-cable graph, subtraction is the only interaction that works;
///     highlighting alone just adds another colour to the noise.
///   - **Search.** Typing filters by name and dims the rest rather than
///     removing it, so nothing reflows under the cursor.
///   - **Motion with a job.** Nodes spring in on first sight, cables carry
///     particles at a rate set by throughput, and the machine breathes. Nothing
///     animates that is not reporting something.
struct GraphCanvasView: View {
    let scene: GraphScene
    var stats: GraphStats?
    /// True while the detail panel is open, so the canvas can give up the
    /// space it occupies. Otherwise selecting a node on the right hides the
    /// exact fan the panel is describing.
    var panelOpen: Bool = false
    /// Space the left rail and any open side panel occupy. The canvas insets by
    /// this so a panel never covers the graph - it sits beside it.
    var leadingInset: CGFloat = 0
    var onTapNode: (GraphNode) -> Void

    @EnvironmentObject private var icons: IconCache
    @State private var hoveredID: String?
    @State private var focusedApp: String?
    @State private var query: String = ""
    /// Hide everything that is merely open, leaving only what is moving now.
    @State private var liveOnly = false

    private var nodes: [GraphNode] { scene.nodes }
    private var edges: [GraphEdge] { scene.edges }

    /// Anything touched by a cable that carried traffic recently.
    private var liveIDs: Set<String> {
        var set: Set<String> = ["mac"]
        for e in edges where e.isActive {
            set.insert(e.from)
            set.insert(e.to)
        }
        return set
    }

    /// The app whose fan is currently emphasised: a click wins, otherwise
    /// hovering an app previews the same thing. Hover-to-preview means you can
    /// sweep the ring and read each fan without committing to anything.
    private var emphasisedApp: String? {
        if let focusedApp { return focusedApp }
        if let hoveredID, hoveredID.hasPrefix("p:") { return hoveredID }
        return nil
    }

    var body: some View {
        ZStack(alignment: .top) {
            CanvasViewport(
                content: { graphContent },
                canvasSize: scene.canvasSize,
                focalPoint: nodes.first(where: { $0.kind == .machine }).map { CGPoint(x: $0.x, y: $0.y) },
                initialScale: 1.75
            )
            // Clear of the toolbar rather than under it, and clear of the side
            // panels: the canvas gives up exactly the space they take, so the
            // graph is never hidden behind one.
            .padding(.top, 68)
            .padding(.trailing, panelOpen ? 416 : 0)
            .padding(.leading, leadingInset)
            .animation(Motion.snap, value: panelOpen)
            .animation(Motion.snap, value: leadingInset)
            header
                .padding(.horizontal, 18)
                .padding(.top, 14)
        }
        .background(Theme.canvas)
        .onExitCommand { clearFocus() }
    }

    // MARK: - Emphasis

    /// How lit a node or cable should be, given focus and search. One function
    /// so a node and its cable can never disagree.
    private func emphasis(nodeID: String, title: String) -> Double {
        var value = 1.0
        if liveOnly, !liveIDs.contains(nodeID) { return 0 }
        if let app = emphasisedApp, !nodeID.hasPrefix(app), nodeID != "mac" {
            value = 0.10
        }
        if !query.isEmpty {
            let hit = title.localizedCaseInsensitiveContains(query)
            value = min(value, hit ? 1.0 : 0.10)
        }
        return value
    }

    /// Emphasis multiplies the bloom and particles, never the cable itself -
    /// the cable stays solid so the graph never looks half-erased.
    private func edgeEmphasis(_ edge: GraphEdge) -> Double {
        if liveOnly, !edge.isActive { return 0 }
        guard emphasisedApp != nil || !query.isEmpty else { return 1 }
        let a = nodes.first { $0.id == edge.from }
        let b = nodes.first { $0.id == edge.to }
        let ea = a.map { emphasis(nodeID: $0.id, title: $0.title) } ?? 1
        let eb = b.map { emphasis(nodeID: $0.id, title: $0.title) } ?? 1
        return max(ea, eb) < 1 ? 0.06 : 1
    }

    private func clearFocus() {
        withAnimation(Motion.focus) {
            focusedApp = nil
            query = ""
            liveOnly = false
        }
    }

    // MARK: - Content

    private var graphContent: some View {
        ZStack {
            GridBackground(spacing: 44).allowsHitTesting(false)

            TimelineView(.animation(minimumInterval: 1.0 / 30.0)) { timeline in
                Canvas { context, _ in
                    drawEdges(&context, time: timeline.date.timeIntervalSinceReferenceDate)
                }
                .allowsHitTesting(false)
            }

            if let mac = nodes.first(where: { $0.kind == .machine }) {
                machineView(mac)
            }

            ForEach(Array(nodes.filter { $0.kind != .machine }.enumerated()), id: \.element.id) { pair in
                nodeView(pair.element, index: pair.offset)
            }
        }
        .onAppear { preloadIcons() }
        .onChange(of: nodes.map(\.id)) { _, _ in preloadIcons() }
    }

    // MARK: - Machine

    private func machineView(_ mac: GraphNode) -> some View {
        // Clickable: the machine is "this whole device", and tapping it opens a
        // session overview - what everything is talking to - rather than one fan.
        Button { onTapNode(mac) } label: {
            VStack(spacing: 12) {
                MacBookAssetView(width: 230)
                    .floatPulse()
                Text(mac.title)
                    .font(TypeStyle.title(13))
                    .foregroundStyle(Theme.ink)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 6)
                    .glassCapsule(rimOpacity: 0.22, shadowRadius: 12, shadowY: 4)
            }
        }
        .buttonStyle(.plain)
        .help("Everything this machine is talking to")
        .position(x: mac.x, y: mac.y)
    }

    // MARK: - Nodes

    private func nodeView(_ node: GraphNode, index: Int) -> some View {
        let hovered = hoveredID == node.id
        let level = emphasis(nodeID: node.id, title: node.title)
        return Button { tap(node) } label: {
            VStack(spacing: 9) {
                nodeGlyph(node, hovered: hovered)
                nodeLabel(node, hovered: hovered)
            }
            .frame(width: node.kind == .process ? 150 : 138)
        }
        .buttonStyle(.plain)
        .staggerAppear(index: min(index, 24))
        .opacity(level)
        .position(x: node.x, y: node.y)
        .zIndex(hovered ? 10 : (node.kind == .process ? 2 : 1))
        .animation(Motion.focus, value: level)
        .onHover { inside in
            withAnimation(Motion.hover) {
                hoveredID = inside ? node.id : (hoveredID == node.id ? nil : hoveredID)
            }
        }
    }

    private func tap(_ node: GraphNode) {
        if node.kind == .process {
            withAnimation(Motion.focus) {
                focusedApp = (focusedApp == node.id) ? nil : node.id
            }
        }
        onTapNode(node)
    }

    private func nodeGlyph(_ node: GraphNode, hovered: Bool) -> some View {
        let accent = Theme.accent(node.accentHue)
        let focused = focusedApp == node.id
        return ZStack {
            // The accent lives behind the glass as a coloured pool, not as a
            // border. Borders read as chrome; light through glass reads as depth.
            Circle()
                .fill(accent.opacity(hovered || focused ? 0.30 : 0.16))
                .blur(radius: node.size * 0.30)
                .frame(width: node.size * 0.95, height: node.size * 0.95)

            glyphContent(node)
                .frame(width: node.size * 0.58, height: node.size * 0.58)
                .padding(node.size * 0.21)
                .glassCard(
                    cornerRadius: node.size * 0.30,
                    rimOpacity: hovered || focused ? 0.55 : 0.26,
                    shadowRadius: hovered ? 18 : 10,
                    shadowY: hovered ? 8 : 4
                )
        }
        .frame(width: node.size, height: node.size)
        .scaleEffect(hovered ? 1.09 : (focused ? 1.04 : 1))
        .animation(Motion.hover, value: hovered)
    }

    /// Icon if we have one, otherwise a monogram. The build before last fell
    /// back to an SF Symbol that rendered as a "prohibited" sign on every
    /// unresolved node, so the map read as sixty blocked things.
    @ViewBuilder
    private func glyphContent(_ node: GraphNode) -> some View {
        if let img = icons.image(url: node.iconURL) ?? icons.image(path: node.localIconPath) {
            Image(nsImage: img)
                .resizable()
                .interpolation(.high)
                .aspectRatio(contentMode: .fit)
        } else if node.kind == .intermediate {
            Image(systemName: "ellipsis")
                .font(.system(size: node.size * 0.26, weight: .semibold))
                .foregroundStyle(Theme.inkSecondary)
        } else if isAddress(node.title) {
            // Tracked, just not yet named. A monogram of "2403:300::13" is the
            // character "2", which reads as a count and says nothing.
            Image(systemName: "point.3.filled.connected.trianglepath.dotted")
                .font(.system(size: node.size * 0.24, weight: .regular))
                .foregroundStyle(Theme.accent(node.accentHue).opacity(0.75))
        } else {
            Text(monogram(node.title))
                .font(.system(size: node.size * 0.30, weight: .semibold, design: .rounded))
                .foregroundStyle(Theme.accent(node.accentHue))
        }
    }

    /// A bare IPv4/IPv6 literal - i.e. something the daemon could not name.
    private func isAddress(_ s: String) -> Bool {
        if s.contains(":") { return true }
        let parts = s.split(separator: ".")
        return parts.count == 4 && parts.allSatisfy { Int($0) != nil }
    }

    private func monogram(_ s: String) -> String {
        let cleaned = s.replacingOccurrences(of: "www.", with: "")
        guard let first = cleaned.first(where: { $0.isLetter || $0.isNumber }) else { return "\u{2022}" }
        return String(first).uppercased()
    }

    private func nodeLabel(_ node: GraphNode, hovered: Bool) -> some View {
        VStack(spacing: 1) {
            Text(node.title)
                .font(node.kind == .process ? TypeStyle.title(12) : TypeStyle.body(11))
                .foregroundStyle(node.kind == .process ? Theme.ink : (hovered ? Theme.ink : Theme.inkSecondary))
                .lineLimit(1)
                .truncationMode(.middle)
            if node.bytes > 0 {
                Text(ByteFormat.tight(node.bytes))
                    .font(TypeStyle.mono(9))
                    .foregroundStyle(Theme.inkTertiary)
                    .contentTransition(.numericText())
            }
        }
        .padding(.horizontal, 7)
        .padding(.vertical, 3)
        .background(
            RoundedRectangle(cornerRadius: 6, style: .continuous)
                .fill(Theme.canvas.opacity(0.72))
        )
        .fixedSize(horizontal: false, vertical: true)
    }

    // MARK: - Edges

    private func drawEdges(_ context: inout GraphicsContext, time: Double) {
        let maxBytes = edges.map(\.bytes).max() ?? 1
        let now = Date(timeIntervalSinceReferenceDate: time)
        EdgeBirth.prune(live: Set(edges.map(\.id)))

        for edge in edges {
            guard edge.routePoints.count == 4 else { continue }
            let level = edgeEmphasis(edge)
            guard level > 0 else { continue }
            let pts = edge.routePoints

            // Cables draw themselves in from the machine outward when they
            // first appear, so a new connection is something you notice
            // happening rather than something that is suddenly just there.
            let grown = EdgeBirth.progress(edge.id, now: now, duration: 0.75)
            guard grown > 0.01 else { continue }

            let base = Theme.lineWidth(bytes: edge.bytes, maxBytes: maxBytes, style: edge.style)
            // Full opacity. A translucent cable picks up the grid behind it and
            // reads as washed out; dimming is done with colour, not alpha.
            let shading = GraphicsContext.Shading.linearGradient(
                Gradient(colors: [edge.colorStart, edge.colorEnd]),
                startPoint: pts[0], endPoint: pts[3]
            )

            // Live cables get a soft bloom underneath. That is the whole
            // signal: lit means packets are crossing right now, grey means the
            // connection is open and idle.
            if edge.isActive, level > 0.3 {
                var whole = Path()
                whole.move(to: pts[0])
                whole.addCurve(to: pts[3], control1: pts[1], control2: pts[2])
                context.stroke(
                    whole,
                    with: .color(edge.colorEnd.opacity(0.16 * level)),
                    style: StrokeStyle(lineWidth: base * 3.2, lineCap: .round)
                )
            }

            // Tapered: thick where it leaves the machine, thin where it
            // arrives. A constant-width stroke reads as a wire diagram; a
            // taper reads as flow, and it tells you which way is outward
            // without needing an arrowhead.
            let segments = 18
            for i in 0..<segments {
                let t0 = Double(i) / Double(segments)
                if t0 >= grown { break }
                let t1 = min(Double(i + 1) / Double(segments), grown)
                let a = GraphPathRouter.bezierPoint(pts, t: CGFloat(t0))
                let b = GraphPathRouter.bezierPoint(pts, t: CGFloat(t1))
                var seg = Path()
                seg.move(to: a)
                seg.addLine(to: b)
                let w = base * (1 - 0.62 * t0)
                context.stroke(seg, with: shading, style: StrokeStyle(lineWidth: w, lineCap: .round))
            }

            guard edge.isActive, level > 0.3, grown > 0.9 else { continue }

            // Particle count and speed both come from throughput, so a busy
            // cable visibly carries more than a quiet one. Capped, because
            // beyond three dots per cable it stops reading as flow.
            let rank = maxBytes > 0 ? min(1, log(Double(edge.bytes) + 1) / log(Double(maxBytes) + 1)) : 0
            let count = 1 + Int(rank * 2)
            let speed = 0.14 + rank * 0.22
            for k in 0..<count {
                let phase = (time * speed + edge.stagger + Double(k) / Double(count))
                    .truncatingRemainder(dividingBy: 1)
                let tip = GraphPathRouter.bezierPoint(pts, t: CGFloat(phase))
                // Fade in and out at the ends so dots arrive rather than blink,
                // and shrink as they travel, matching the cable's taper.
                let fade = sin(phase * .pi)
                let r = (edge.style == .hub ? 2.9 : 2.3) * (1 - 0.45 * phase)
                context.fill(
                    Path(ellipseIn: CGRect(x: tip.x - r, y: tip.y - r, width: r * 2, height: r * 2)),
                    with: .color(edge.colorEnd.opacity(0.95 * fade * level))
                )
            }
        }
    }

    // MARK: - Header

    private var header: some View {
        HStack(spacing: 16) {
            Text("ohmyosi")
                .font(TypeStyle.title(12))
                .foregroundStyle(Theme.ink)

            if let stats {
                Divider().frame(height: 13).overlay(Theme.cardBorder)
                statPill("\(stats.apps)", "apps")
                statPill("\(stats.destinations)", "destinations")
                statPill("\(stats.links)", "paths")
                if let names = stats.nameEvidence {
                    statPill(names, "names flow/address/unknown")
                }
                if let capture = stats.captureHealth {
                    statPill(capture, "capture")
                }
            }

            Spacer(minLength: 12)
            legend
            liveToggle
            searchField

            if focusedApp != nil || !query.isEmpty || liveOnly {
                Button(action: clearFocus) {
                    Text("clear")
                        .font(TypeStyle.label(10))
                        .foregroundStyle(Theme.ink)
                        .padding(.horizontal, 9)
                        .padding(.vertical, 4)
                        .glassCapsule(rimOpacity: 0.35, shadowRadius: 6, shadowY: 2)
                }
                .buttonStyle(.plain)
                .transition(.opacity.combined(with: .scale))
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 9)
        .glassCapsule(material: .regularMaterial, rimOpacity: 0.28, shadowRadius: 20, shadowY: 8)
    }

    /// Says what the two cable states mean, because a colour convention nobody
    /// explained is just a colour.
    private var legend: some View {
        HStack(spacing: 10) {
            legendDot(Theme.palette[0], "moving")
            legendDot(Theme.idleWire, "open")
        }
    }

    private func legendDot(_ color: Color, _ label: String) -> some View {
        HStack(spacing: 5) {
            Capsule().fill(color).frame(width: 14, height: 3)
            Text(label).font(TypeStyle.caption(10)).foregroundStyle(Theme.inkSecondary)
        }
    }

    private var liveToggle: some View {
        Button {
            withAnimation(Motion.focus) { liveOnly.toggle() }
        } label: {
            HStack(spacing: 5) {
                Image(systemName: liveOnly ? "bolt.fill" : "bolt")
                    .font(.system(size: 10, weight: .semibold))
                Text("live only")
                    .font(TypeStyle.label(10))
            }
            .foregroundStyle(liveOnly ? Theme.palette[0] : Theme.inkSecondary)
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .glassCapsule(rimOpacity: liveOnly ? 0.5 : 0.18, shadowRadius: 4, shadowY: 1)
        }
        .buttonStyle(.plain)
        .help("Show only connections carrying traffic right now")
    }

    private var searchField: some View {
        HStack(spacing: 6) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 10, weight: .medium))
                .foregroundStyle(Theme.inkTertiary)
            TextField("filter", text: $query)
                .textFieldStyle(.plain)
                .font(TypeStyle.body(11))
                .foregroundStyle(Theme.ink)
                .frame(width: 130)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 5)
        .glassCapsule(rimOpacity: 0.18, shadowRadius: 4, shadowY: 1)
    }

    private func statPill(_ value: String, _ label: String) -> some View {
        HStack(spacing: 5) {
            Text(value)
                .font(TypeStyle.mono(11))
                .foregroundStyle(Theme.ink)
                .contentTransition(.numericText())
            Text(label).font(TypeStyle.caption(10)).foregroundStyle(Theme.inkSecondary)
        }
    }

    private func preloadIcons() {
        icons.preload(
            urls: nodes.compactMap(\.iconURL),
            paths: nodes.compactMap(\.localIconPath)
        )
    }
}

struct GraphStats {
    let apps: Int
    let destinations: Int
    let links: Int
    let nameEvidence: String?
    let captureHealth: String?
}
