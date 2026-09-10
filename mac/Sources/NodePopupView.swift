import SwiftUI

/// The detail panel.
///
/// This was a centred modal over a dimming scrim, which meant selecting a node
/// covered the graph that selecting it had just focused - the two interactions
/// cancelled each other out. As a side panel the focused fan stays visible
/// beside its own detail, which is the whole reason for focusing in the first
/// place.
struct NodePopupView: View {
    @EnvironmentObject private var store: MonitorStore
    let node: GraphNode
    let flows: [Flow]
    let processes: [Int32: ProcessInfo]
    var onClose: () -> Void

    /// The app name this node represents, when it is a process node - what a
    /// "block this app" rule matches on.
    private var appName: String? {
        guard node.kind == .process else { return nil }
        if let pid = flows.first?.pid, let p = processes[pid] { return p.displayName }
        return node.title
    }

    /// The signing verdict for a process node, from any of its flows' PIDs.
    private var signing: (status: String, by: String?)? {
        guard node.kind == .process else { return nil }
        for f in flows {
            if let p = processes[f.pid], let s = p.signing, !s.isEmpty {
                return (s, p.signed_by)
            }
        }
        return nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider().overlay(Theme.cardBorder)
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 10) {
                    ForEach(flows.prefix(40), id: \.id) { flow in
                        flowRow(flow)
                    }
                    if flows.count > 40 {
                        Text("+\(flows.count - 40) more flows")
                            .font(TypeStyle.caption(10))
                            .foregroundStyle(Theme.inkTertiary)
                            .padding(.top, 4)
                    }
                }
                .padding(16)
            }
        }
        .frame(width: 400)
        .frame(maxHeight: .infinity)
        .glassCard(cornerRadius: 20, material: .regularMaterial, rimOpacity: 0.26, shadowRadius: 34, shadowY: 0)
    }

    private var header: some View {
        HStack(alignment: .top, spacing: 14) {
            AppIconView(
                url: node.iconURL,
                localPath: node.localIconPath,
                symbol: node.kind == .process ? "app.fill" : "globe",
                size: 46,
                accentHue: node.accentHue
            )
            VStack(alignment: .leading, spacing: 5) {
                Text(node.title)
                    .font(TypeStyle.title(15))
                    .foregroundStyle(Theme.ink)
                    .lineLimit(2)
                if let sub = node.subtitle, !sub.isEmpty {
                    Text(sub)
                        .font(TypeStyle.body(11))
                        .foregroundStyle(Theme.inkSecondary)
                }
                Text("\(ByteFormat.compact(node.bytes))  ·  \(flows.count) flow\(flows.count == 1 ? "" : "s")")
                    .font(TypeStyle.mono(10))
                    .foregroundStyle(Theme.inkTertiary)
                if let signing {
                    signingBadge(signing.status, by: signing.by)
                }
                if let app = appName {
                    blockAppButton(app)
                }
            }
            Spacer(minLength: 0)
            VStack(spacing: 8) {
                Button(action: onClose) {
                    Image(systemName: "xmark")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(Theme.inkSecondary)
                        .frame(width: 26, height: 26)
                        .glassCapsule(rimOpacity: 0.22, shadowRadius: 4, shadowY: 1)
                }
                .buttonStyle(.plain)
                InfoButton(text: """
                Each row is one connection. The coloured band and number are how much it wants a second look, and the sentences under it say why.

                **DIRECT IP** the machine never named where it was going. **NEW** first time this app reached here. **UNSIGNED** the binary's origin can't be verified. The hand blocks the destination.
                """, edge: .leading)
            }
        }
        .padding(18)
    }

    private func signingBadge(_ status: String, by: String?) -> some View {
        let untrusted = status == "adhoc" || status == "unsigned"
        let color = untrusted ? Theme.band(.loud) : Theme.inkSecondary
        let text: String = {
            switch status {
            case "apple": return "Apple-signed"
            case "developer-id": return "Developer ID" + (by.map { " · \($0)" } ?? "")
            case "signed": return by ?? "signed"
            case "adhoc": return "ad-hoc signed — provenance unverifiable"
            case "unsigned": return "UNSIGNED"
            default: return status
            }
        }()
        return Text(text)
            .font(TypeStyle.caption(9))
            .foregroundStyle(color)
            .lineLimit(1)
            .padding(.top, 1)
    }

    private func blockAppButton(_ app: String) -> some View {
        let blocked = store.rules.contains { $0.enabled && $0.isBlock && $0.scope == "app" && $0.match.lowercased() == app.lowercased() }
        return Button {
            if blocked {
                for r in store.rules where r.scope == "app" && r.match.lowercased() == app.lowercased() {
                    store.deleteRule(id: r.id)
                }
            } else {
                store.addRule(scope: "app", match: app, note: "from inspector")
            }
        } label: {
            HStack(spacing: 4) {
                Image(systemName: blocked ? "hand.raised.fill" : "hand.raised")
                Text(blocked ? "Unblock this app" : "Block this app")
            }
            .font(TypeStyle.label(9))
            .foregroundStyle(blocked ? Theme.band(.loud) : Theme.inkSecondary)
            .padding(.horizontal, 8).padding(.vertical, 3)
            .glassCapsule(rimOpacity: blocked ? 0.4 : 0.2, shadowRadius: 3, shadowY: 1)
        }
        .buttonStyle(.plain)
        .padding(.top, 3)
    }

    @ViewBuilder
    private func flowRow(_ flow: Flow) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack(spacing: 8) {
                FaviconView(domain: flow.remote.domain ?? flow.remote.host, favicon: flow.remote.favicon, size: 15)
                Text(flow.remote.displayName)
                    .font(TypeStyle.mono(12))
                    .foregroundStyle(Theme.ink)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer(minLength: 6)
                Text(ByteFormat.compact(flow.totalBytes))
                    .font(TypeStyle.mono(10))
                    .foregroundStyle(Theme.inkSecondary)
                blockDestButton(flow)
            }

            HStack(spacing: 5) {
                // Lead with the score's verdict when it is asking for attention.
                if flow.band.wantsAttention {
                    bandTag(flow.band, score: flow.suspicionScore)
                }
                if let src = flow.remote.host_src { tag(src.uppercased(), tone: .normal) }
                // The honest flags. These are the ones worth seeing without
                // opening anything: nobody announced a name for this, or the
                // connection predates us so its handshake is unrecoverable.
                if flow.direct_ip == true { tag("DIRECT IP", tone: .warn) }
                if flow.first_contact == true { tag("NEW", tone: .warn) }
                if processes[flow.pid]?.untrustedSignature == true { tag("UNSIGNED", tone: .warn) }
                if flow.pre_existing == true { tag("PRE-EXISTING", tone: .muted) }
                Text("\(flow.proto):\(flow.remote.port)")
                    .font(TypeStyle.mono(9))
                    .foregroundStyle(Theme.inkTertiary)
            }

            // Why the scorer flagged it. Shown for anything above quiet, because
            // the reasons are the score - the number alone earns no belief.
            if let reasons = flow.reasons, !reasons.isEmpty, flow.band != .quiet {
                VStack(alignment: .leading, spacing: 3) {
                    ForEach(Array(reasons.enumerated()), id: \.offset) { _, reason in
                        HStack(alignment: .top, spacing: 6) {
                            Circle().fill(Theme.band(flow.band))
                                .frame(width: 3, height: 3).padding(.top, 5)
                            Text(reason)
                                .font(TypeStyle.caption(10))
                                .foregroundStyle(Theme.inkSecondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }
                .padding(.top, 1)
            }

            if let ja4 = flow.ja4, !ja4.isEmpty {
                HStack(spacing: 6) {
                    Text("JA4")
                        .font(TypeStyle.label(9))
                        .foregroundStyle(Theme.inkTertiary)
                    Text(ja4)
                        .font(TypeStyle.mono(10))
                        .foregroundStyle(Theme.inkSecondary)
                        .textSelection(.enabled)
                        .lineLimit(1).truncationMode(.middle)
                }
            }

            if let trail = flow.remote.trail, !trail.isEmpty {
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(Array(trail.prefix(4).enumerated()), id: \.offset) { i, line in
                        HStack(alignment: .top, spacing: 6) {
                            Text("\(i + 1)")
                                .font(TypeStyle.mono(9))
                                .foregroundStyle(Theme.inkTertiary)
                                .frame(width: 10, alignment: .trailing)
                            Text(line)
                                .font(TypeStyle.caption(10))
                                .foregroundStyle(Theme.inkSecondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }
                .padding(.top, 1)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(Color.white.opacity(0.04))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .strokeBorder(Color.white.opacity(0.05), lineWidth: 0.5)
        )
    }

    /// Block a single flow's destination: by domain if the machine named it
    /// (covers its subdomains), otherwise by the bare address.
    @ViewBuilder
    private func blockDestButton(_ flow: Flow) -> some View {
        let domain = flow.remote.domain ?? flow.remote.host
        let ip = flow.remote.ip
        let blocked = store.isBlocked(domain: flow.remote.domain, host: flow.remote.host, ip: ip)
        Button {
            if blocked {
                let targets = [domain?.lowercased(), ip.lowercased()].compactMap { $0 }
                for r in store.rules where targets.contains(r.match.lowercased()) {
                    store.deleteRule(id: r.id)
                }
            } else if let d = domain, !d.isEmpty {
                store.addRule(scope: "domain", match: d, note: "from inspector")
            } else {
                store.addRule(scope: "dest", match: ip, note: "from inspector")
            }
        } label: {
            Image(systemName: blocked ? "hand.raised.fill" : "hand.raised")
                .font(.system(size: 10, weight: .semibold))
                .foregroundStyle(blocked ? Theme.band(.loud) : Theme.inkTertiary)
        }
        .buttonStyle(.plain)
        .help(blocked ? "Remove block" : "Block this destination")
    }

    private func bandTag(_ band: SuspicionBand, score: Int) -> some View {
        let color = Theme.band(band)
        return HStack(spacing: 4) {
            Text(band.rawValue.uppercased())
            Text("\(score)").font(TypeStyle.mono(9))
        }
        .font(TypeStyle.label(9))
        .foregroundStyle(color)
        .padding(.horizontal, 6)
        .padding(.vertical, 2)
        .background(Capsule().fill(color.opacity(0.14)))
        .overlay(Capsule().strokeBorder(color.opacity(0.3), lineWidth: 0.5))
    }

    private enum Tone { case normal, warn, muted }

    private func tag(_ text: String, tone: Tone) -> some View {
        let color: Color = {
            switch tone {
            case .normal: return Theme.inkSecondary
            case .warn: return Color(red: 0.98, green: 0.44, blue: 0.44)
            case .muted: return Theme.inkTertiary
            }
        }()
        return Text(text)
            .font(TypeStyle.label(9))
            .foregroundStyle(color)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(
                Capsule().fill(color.opacity(0.12))
            )
            .overlay(Capsule().strokeBorder(color.opacity(0.25), lineWidth: 0.5))
    }
}
