import SwiftUI

/// The left rail: a thin, always-present column of controls that switches which
/// side panel is open. It is deliberately narrow, and the canvas insets by the
/// rail plus whatever panel is open, so nothing here ever sits on top of the
/// graph - it sits beside it.
///
/// Every control carries a written label. An icon alone is a guess; the whole
/// point of this app is that you never have to guess what you are looking at.
enum RailMetrics {
    static let railWidth: CGFloat = 76
    static let panelWidth: CGFloat = 320
}

struct LeftRail: View {
    @EnvironmentObject private var store: MonitorStore

    var body: some View {
        VStack(spacing: 4) {
            item(.attention, system: "dot.radiowaves.left.and.right", label: "Attention",
                 help: "Connections worth a second look, each with its reasons",
                 badge: store.attentionFlows.count,
                 tint: store.attentionFlows.isEmpty ? nil : Theme.band(store.peakBand))
            item(.sites, system: "globe", label: "Sites",
                 help: "Every destination seen this session, live or not",
                 badge: store.destinations.count)
            item(.rules, system: "hand.raised", label: "Rules",
                 help: "Block or allow by app, domain or address",
                 badge: store.ruleGroups.count + store.manualRules.count)
            item(.system, system: "gearshape", label: "Controls",
                 help: "Capture, enforcement and identity settings",
                 tint: store.enforcing ? Theme.band(.loud) : nil)

            Spacer(minLength: 8)

            actionButton(system: "square.and.arrow.up", label: "Export",
                         help: "Write this session out as a recording you can replay") {
                store.exportSession()
            }
            toggleButton(system: store.showSelfTraffic ? "eye.fill" : "eye",
                         label: "Self", on: store.showSelfTraffic,
                         help: "Show ohmyosi's own traffic (lookups it makes on your behalf)") {
                store.showSelfTraffic.toggle()
            }
            VStack(spacing: 2) {
                InfoButton(text: """
                **ohmyosi** — every connection leaving this machine, which app opened it, and where it actually went.

                • **Attention** — connections worth a second look, with reasons
                • **Sites** — everything seen this session, live or not
                • **Rules** — block or allow by app, domain or address
                • **Controls** — capture and enforcement settings

                **Export** writes the session out as a replayable recording. **Self** toggles ohmyosi's own lookups.
                """, edge: .trailing)
                railLabel("About", active: false)
            }
        }
        .padding(.vertical, 12)
        .frame(width: RailMetrics.railWidth)
        .frame(maxHeight: .infinity)
        .glassCard(cornerRadius: 20, material: .regularMaterial, rimOpacity: 0.22, shadowRadius: 24, shadowY: 0)
    }

    /// Counts are shown in full. A badge that says "99+" hides exactly the
    /// information the badge exists to give you, and every count here is one a
    /// person can actually act on: sites they can open, rules they can edit.
    /// An imported blocklist counts as the one rule it is, not as its 135,000
    /// domains - the badge tracks what the panel shows.
    private func badgeText(_ n: Int) -> String {
        n >= 100_000 ? "99999+" : "\(n)"
    }

    private func railLabel(_ text: String, active: Bool) -> some View {
        Text(text)
            .font(.system(size: 9, weight: active ? .semibold : .medium))
            .foregroundStyle(active ? Theme.ink : Theme.inkTertiary)
            .lineLimit(1)
            .minimumScaleFactor(0.8)
            .frame(width: RailMetrics.railWidth - 8)
    }

    private func item(_ panel: LeftPanel, system: String, label: String, help: String,
                      badge: Int = 0, tint: Color? = nil) -> some View {
        let active = store.leftPanel == panel
        return Button {
            withAnimation(Motion.snap) { store.leftPanel = active ? .none : panel }
        } label: {
            VStack(spacing: 2) {
                ZStack(alignment: .topTrailing) {
                    Image(systemName: system)
                        .font(.system(size: 15, weight: .medium))
                        .foregroundStyle(active ? Theme.ink : (tint ?? Theme.inkSecondary))
                        .frame(width: 46, height: 30)
                        .background(
                            RoundedRectangle(cornerRadius: 9, style: .continuous)
                                .fill(active ? Color.white.opacity(0.10) : .clear)
                        )
                    if badge > 0 {
                        Text(badgeText(badge))
                            .font(TypeStyle.mono(8))
                            .foregroundStyle(Theme.canvasDeep)
                            .padding(.horizontal, 3).padding(.vertical, 1)
                            .background(Capsule().fill(tint ?? Theme.inkSecondary))
                            .offset(x: 7, y: -3)
                    }
                }
                railLabel(label, active: active)
            }
            .padding(.bottom, 4)
        }
        .buttonStyle(.plain)
        .help("\(label) — \(help)")
    }

    private func actionButton(system: String, label: String, help: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            VStack(spacing: 2) {
                Image(systemName: system)
                    .font(.system(size: 14, weight: .medium))
                    .foregroundStyle(Theme.inkSecondary)
                    .frame(width: 46, height: 26)
                railLabel(label, active: false)
            }
            .padding(.bottom, 4)
        }
        .buttonStyle(.plain)
        .help("\(label) — \(help)")
    }

    private func toggleButton(system: String, label: String, on: Bool, help: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            VStack(spacing: 2) {
                Image(systemName: system)
                    .font(.system(size: 14, weight: .medium))
                    .foregroundStyle(on ? Theme.palette[4] : Theme.inkTertiary)
                    .frame(width: 46, height: 26)
                railLabel(label, active: on)
            }
            .padding(.bottom, 4)
        }
        .buttonStyle(.plain)
        .help("\(label) — \(help)")
    }
}
