import SwiftUI

/// The list that answers the one question someone opens this tool asking: what
/// is my machine doing that I did not expect?
///
/// It shows the flows the scorer ranked worth a look, loudest first, each with
/// the sentences behind its score. The number is never shown on its own - a
/// score you cannot argue with is one you cannot trust - so every row unfolds
/// into the reasons that earned it, and the person decides what they mean.
struct TriagePanel: View {
    let flows: [Flow]
    let processes: [Int32: ProcessInfo]
    var onCollapse: () -> Void

    @State private var expanded: Set<String> = []

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            if flows.isEmpty {
                emptyState
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 8) {
                        ForEach(flows.prefix(14), id: \.id) { flow in
                            row(flow)
                        }
                    }
                    .padding(12)
                }
            }
        }
        .frame(width: 320)
        .frame(maxHeight: 460)
        .glassCard(cornerRadius: 18, material: .regularMaterial, rimOpacity: 0.24, shadowRadius: 30, shadowY: 0)
    }

    private var header: some View {
        HStack(spacing: 8) {
            Image(systemName: "dot.radiowaves.left.and.right")
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(flows.isEmpty ? Theme.inkTertiary : Theme.band(flows.first?.band ?? .quiet))
            Text("Attention")
                .font(TypeStyle.title(13))
                .foregroundStyle(Theme.ink)
            if !flows.isEmpty {
                Text("\(flows.count)")
                    .font(TypeStyle.mono(10))
                    .foregroundStyle(Theme.inkSecondary)
                    .padding(.horizontal, 6).padding(.vertical, 1)
                    .background(Capsule().fill(Color.white.opacity(0.06)))
            }
            InfoButton(text: """
            Connections the scorer thinks are worth a look, loudest first. This is **not** malware detection — no threat feed, no signatures. It sums ordinary facts that are collectively unusual.

            Bands: **notable** (amber), **unusual** (orange), **loud** (red). Tap a row for the reasons behind the score — the number never stands alone.
            """)
            Spacer(minLength: 0)
            Button(action: onCollapse) {
                Image(systemName: "chevron.left")
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(Theme.inkSecondary)
                    .frame(width: 24, height: 24)
                    .glassCapsule(rimOpacity: 0.2, shadowRadius: 3, shadowY: 1)
            }
            .buttonStyle(.plain)
        }
        .padding(14)
    }

    private var emptyState: some View {
        VStack(spacing: 8) {
            Image(systemName: "checkmark.shield")
                .font(.system(size: 22, weight: .light))
                .foregroundStyle(Theme.inkTertiary)
            Text("Nothing unusual right now")
                .font(TypeStyle.body(12))
                .foregroundStyle(Theme.inkSecondary)
            Text("Connections scoring quiet or notable are hidden here — the graph shows everything.")
                .font(TypeStyle.caption(10))
                .foregroundStyle(Theme.inkTertiary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity)
        .padding(.horizontal, 24)
        .padding(.vertical, 32)
    }

    @ViewBuilder
    private func row(_ flow: Flow) -> some View {
        let isOpen = expanded.contains(flow.id)
        let proc = processes[flow.pid]
        VStack(alignment: .leading, spacing: 6) {
            Button {
                withAnimation(.easeOut(duration: 0.16)) {
                    if isOpen { expanded.remove(flow.id) } else { expanded.insert(flow.id) }
                }
            } label: {
                HStack(spacing: 9) {
                    // A vertical band stripe: colour is the fastest read of "how
                    // loud", before any number is parsed.
                    RoundedRectangle(cornerRadius: 2)
                        .fill(Theme.band(flow.band))
                        .frame(width: 3, height: 34)
                    VStack(alignment: .leading, spacing: 2) {
                        // Who, then where. The row always leads with a name for
                        // the process - never a blank line above an address,
                        // because "something on your machine" is not an answer.
                        HStack(spacing: 5) {
                            Text(actorName(flow, proc))
                                .font(TypeStyle.body(12))
                                .foregroundStyle(Theme.ink)
                                .lineLimit(1)
                            Image(systemName: "arrow.right")
                                .font(.system(size: 7, weight: .bold))
                                .foregroundStyle(Theme.inkTertiary)
                            Text(flow.remote.displayName)
                                .font(TypeStyle.mono(10))
                                .foregroundStyle(Theme.inkSecondary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                        // The single sentence that earned the most points. The
                        // score is never shown without at least one reason next
                        // to it, open or closed.
                        Text(headlineReason(flow))
                            .font(TypeStyle.caption(10))
                            .foregroundStyle(Theme.inkTertiary)
                            .lineLimit(isOpen ? 3 : 1)
                            .truncationMode(.tail)
                    }
                    Spacer(minLength: 6)
                    Text("\(flow.suspicionScore)")
                        .font(TypeStyle.mono(13))
                        .foregroundStyle(Theme.band(flow.band))
                        .contentTransition(.numericText())
                    Image(systemName: isOpen ? "chevron.up" : "chevron.down")
                        .font(.system(size: 8, weight: .semibold))
                        .foregroundStyle(Theme.inkTertiary)
                }
            }
            .buttonStyle(.plain)

            HStack(spacing: 5) {
                bandChip(flow.band)
                if flow.first_contact == true { chip("NEW", Theme.band(.unusual)) }
                if flow.direct_ip == true { chip("DIRECT IP", Theme.band(.loud)) }
                if proc?.untrustedSignature == true { chip("UNSIGNED", Theme.band(.loud)) }
            }

            if isOpen {
                let rest = Array((flow.reasons ?? []).dropFirst())
                if !rest.isEmpty {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(Array(rest.enumerated()), id: \.offset) { _, reason in
                            HStack(alignment: .top, spacing: 6) {
                                Circle().fill(Theme.band(flow.band)).frame(width: 3, height: 3).padding(.top, 5)
                                Text(reason)
                                    .font(TypeStyle.caption(10))
                                    .foregroundStyle(Theme.inkSecondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }
                    .padding(.top, 2)
                }
                if let ja4 = flow.ja4, !ja4.isEmpty {
                    detailLine("TLS fingerprint", ja4)
                }
                if let signedBy = proc?.signed_by, !signedBy.isEmpty {
                    detailLine("signed by", signedBy)
                }
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(Color.white.opacity(isOpen ? 0.05 : 0.03))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .strokeBorder(Theme.band(flow.band).opacity(0.18), lineWidth: 0.5)
        )
    }

    /// A name for whatever opened this connection. Falls through the app bundle
    /// name, the process name, then the raw pid - and says so plainly when the
    /// kernel gave us nothing, rather than showing an empty line.
    private func actorName(_ flow: Flow, _ proc: ProcessInfo?) -> String {
        if let d = proc?.displayName, !d.isEmpty { return d }
        if !flow.comm.isEmpty { return flow.comm }
        if flow.pid > 0 { return "pid \(flow.pid)" }
        return "unattributed"
    }

    /// The loudest reason, in the scorer's own words. The scorer returns them
    /// in descending point order, so the first one is the one that mattered.
    private func headlineReason(_ flow: Flow) -> String {
        if let r = flow.reasons?.first, !r.isEmpty { return r }
        return "no single reason - see the full breakdown"
    }

    private func detailLine(_ label: String, _ value: String) -> some View {
        HStack(spacing: 6) {
            Text(label)
                .font(TypeStyle.caption(9))
                .foregroundStyle(Theme.inkTertiary)
            Text(value)
                .font(TypeStyle.mono(10))
                .foregroundStyle(Theme.inkSecondary)
                .lineLimit(1)
                .truncationMode(.middle)
        }
        .padding(.top, 2)
    }

    private func bandChip(_ b: SuspicionBand) -> some View {
        chip(b.rawValue.uppercased(), Theme.band(b))
    }

    private func chip(_ text: String, _ color: Color) -> some View {
        Text(text)
            .font(TypeStyle.label(9))
            .foregroundStyle(color)
            .padding(.horizontal, 6).padding(.vertical, 2)
            .background(Capsule().fill(color.opacity(0.12)))
            .overlay(Capsule().strokeBorder(color.opacity(0.25), lineWidth: 0.5))
    }
}
