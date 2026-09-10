import SwiftUI

struct MainView: View {
    @EnvironmentObject private var store: MonitorStore
    @State private var dismissedAlertID: String?

    /// How much space the rail (plus any open panel) takes on the left, so the
    /// canvas can inset by exactly that and never be covered.
    private var leadingInset: CGFloat {
        let base = 12 + RailMetrics.railWidth + 8
        return store.leftPanel == .none ? base : base + RailMetrics.panelWidth + 8
    }

    var body: some View {
        ZStack {
            RadialGradient(
                colors: [Theme.canvas, Theme.canvasDeep],
                center: .center, startRadius: 80, endRadius: 900
            )
            .ignoresSafeArea()

            if !store.showGraph {
                SplashView(connected: store.isConnected) {
                    store.finishSplash()
                }
            } else {
                graphLayer
                leftRegion
                alertLayer
                inspectorLayer
                errorLayer
            }
        }
        .animation(Motion.snap, value: store.popupNode?.id)
        .animation(Motion.snap, value: store.leftPanel)
        .onExitCommand { withAnimation(Motion.snap) { store.popupNode = nil } }
        .preferredColorScheme(.dark)
        .onAppear {
            store.connect()
            if VerifyMode.isActive { store.finishSplash() }
        }
        .onChange(of: store.showGraph) { _, show in
            guard show, let path = VerifyMode.snapshotPath else { return }
            Task { @MainActor in
                try? await Task.sleep(for: .milliseconds(2000))
                let scene = GraphLayout.build(
                    flows: store.visibleFlows,
                    processes: store.processes,
                    hostname: store.host?.hostname.components(separatedBy: ".").first ?? "Mac",
                    viewport: CGSize(width: 1400, height: 960)
                )
                if SnapshotExporter.capture(
                    GraphSnapshotView(scene: scene),
                    size: scene.canvasSize,
                    to: path
                ) {
                    NSApplication.shared.terminate(nil)
                }
            }
        }
        .onDisappear { store.disconnect() }
    }

    // The rail is always present; the panel slides in beside it. Both sit to the
    // left of the graph, which has already given up this space, so nothing here
    // covers the canvas.
    private var leftRegion: some View {
        HStack(alignment: .top, spacing: 8) {
            LeftRail()
            if store.leftPanel != .none {
                activePanel
                    .transition(.move(edge: .leading).combined(with: .opacity))
            }
            Spacer(minLength: 0)
        }
        .padding(.leading, 12)
        .padding(.top, 74)
        .padding(.bottom, 20)
    }

    @ViewBuilder
    private var activePanel: some View {
        switch store.leftPanel {
        case .attention:
            TriagePanel(
                flows: store.attentionFlows,
                processes: store.processes,
                onCollapse: { withAnimation(Motion.snap) { store.leftPanel = .none } }
            )
        case .sites:
            AllSitesView(onCollapse: { withAnimation(Motion.snap) { store.leftPanel = .none } })
        case .rules:
            RulesView(onCollapse: { withAnimation(Motion.snap) { store.leftPanel = .none } })
        case .system:
            SystemView(onCollapse: { withAnimation(Motion.snap) { store.leftPanel = .none } })
        case .none:
            EmptyView()
        }
    }

    private var alertLayer: some View {
        Group {
            if let alert = store.recentAlerts.first, alert.id != dismissedAlertID {
                VStack {
                    alertBanner(alert)
                        .padding(.top, 74)
                        .transition(.move(edge: .top).combined(with: .opacity))
                        .task(id: alert.id) {
                            try? await Task.sleep(for: .seconds(7))
                            withAnimation(Motion.snap) { dismissedAlertID = alert.id }
                        }
                    Spacer()
                }
            }
        }
    }

    private var inspectorLayer: some View {
        Group {
            if let node = store.popupNode {
                HStack(spacing: 0) {
                    Spacer(minLength: 0)
                    NodePopupView(
                        node: node,
                        flows: store.popupFlows,
                        processes: store.processes,
                        onClose: { withAnimation(Motion.snap) { store.popupNode = nil } }
                    )
                    .padding(.trailing, 16)
                    .padding(.top, 74)
                    .padding(.bottom, 76)
                    .transition(.move(edge: .trailing).combined(with: .opacity))
                }
            }
        }
    }

    private var errorLayer: some View {
        Group {
            if let err = store.lastError, !store.isConnected {
                VStack {
                    Spacer()
                    Text(err)
                        .font(TypeStyle.body(13))
                        .padding(.horizontal, 16)
                        .padding(.vertical, 10)
                        .background(Theme.card, in: Capsule())
                        .overlay(Capsule().strokeBorder(Theme.cardBorder, lineWidth: 0.5))
                        .padding(.bottom, 24)
                }
            }
        }
    }

    private func alertBanner(_ alert: Alert) -> some View {
        let band = SuspicionBand(rawValue: alert.band) ?? .notable
        return Button {
            withAnimation(Motion.snap) {
                store.leftPanel = .attention
                dismissedAlertID = alert.id
            }
        } label: {
            HStack(spacing: 10) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(Theme.band(band))
                VStack(alignment: .leading, spacing: 1) {
                    Text("\(alert.comm) → \(alert.dest)")
                        .font(TypeStyle.body(12))
                        .foregroundStyle(Theme.ink)
                        .lineLimit(1)
                    if let reason = alert.reasons?.first {
                        Text(reason)
                            .font(TypeStyle.caption(10))
                            .foregroundStyle(Theme.inkSecondary)
                            .lineLimit(1)
                    }
                }
                Text("\(alert.score)")
                    .font(TypeStyle.mono(13))
                    .foregroundStyle(Theme.band(band))
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            .frame(maxWidth: 420)
            .glassCapsule(rimOpacity: 0.24, shadowRadius: 20, shadowY: 2)
        }
        .buttonStyle(.plain)
    }

    private var graphLayer: some View {
        GeometryReader { geo in
            let scene = GraphLayout.build(
                flows: store.visibleFlows,
                processes: store.processes,
                hostname: store.host?.hostname.components(separatedBy: ".").first ?? "Mac",
                viewport: geo.size
            )
            let stats = GraphStats(
                apps: scene.nodes.filter { $0.kind == .process }.count,
                destinations: scene.nodes.filter { $0.kind == .destination }.count,
                links: scene.edges.filter { $0.style == .link }.count
            )
            GraphCanvasView(
                scene: scene, stats: stats,
                panelOpen: store.popupNode != nil,
                leadingInset: leadingInset
            ) { node in
                withAnimation(Motion.snap) {
                    store.openPopup(for: node, layoutFlows: store.visibleFlows)
                }
            }
        }
    }
}
