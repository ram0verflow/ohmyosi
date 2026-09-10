import SwiftUI

/// Everything this machine has talked to this session - live or not.
///
/// This is the answer to "I have fifty tabs open but the graph shows eight":
/// the graph is what is *moving right now*, because an idle tab holds no
/// connection. This list keeps every destination seen since the daemon started,
/// so nothing quietly drops off once it goes quiet. Each row can be blocked in
/// place.
struct AllSitesView: View {
    @EnvironmentObject private var store: MonitorStore
    var onCollapse: () -> Void

    @State private var query = ""
    private let now = Date().timeIntervalSince1970

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            searchBar
            let sites = store.sites(matching: query)
            if sites.isEmpty {
                empty
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 6) {
                        ForEach(sites) { site in row(site) }
                    }
                    .padding(12)
                }
            }
        }
        .frame(width: RailMetrics.panelWidth)
        .frame(maxHeight: .infinity)
        .glassCard(cornerRadius: 18, material: .regularMaterial, rimOpacity: 0.24, shadowRadius: 30, shadowY: 0)
    }

    private var header: some View {
        HStack(spacing: 8) {
            Image(systemName: "globe").font(.system(size: 12, weight: .semibold)).foregroundStyle(Theme.inkSecondary)
            Text("All sites").font(TypeStyle.title(13)).foregroundStyle(Theme.ink)
            Text("\(store.destinations.count)").font(TypeStyle.mono(10)).foregroundStyle(Theme.inkSecondary)
                .padding(.horizontal, 6).padding(.vertical, 1)
                .background(Capsule().fill(Color.white.opacity(0.06)))
            InfoButton(text: """
            **Everything seen this session** — live or not. The graph shows only what is moving right now; this keeps every destination since the daemon started, so idle tabs do not vanish.

            The dot is **green** when traffic is crossing now, grey when the connection is idle or gone. The hand blocks a destination.
            """)
            Spacer(minLength: 0)
            collapseButton(onCollapse)
        }
        .padding(14)
    }

    private var searchBar: some View {
        HStack(spacing: 6) {
            Image(systemName: "magnifyingglass").font(.system(size: 10)).foregroundStyle(Theme.inkTertiary)
            TextField("filter sites, orgs, apps", text: $query)
                .textFieldStyle(.plain).font(TypeStyle.body(11)).foregroundStyle(Theme.ink)
        }
        .padding(.horizontal, 10).padding(.vertical, 7)
        .background(RoundedRectangle(cornerRadius: 9).fill(Color.white.opacity(0.05)))
        .padding(.horizontal, 12)
        .padding(.bottom, 8)
    }

    private var empty: some View {
        VStack(spacing: 6) {
            Image(systemName: "globe").font(.system(size: 20, weight: .light)).foregroundStyle(Theme.inkTertiary)
            Text("No destinations yet").font(TypeStyle.body(12)).foregroundStyle(Theme.inkSecondary)
        }
        .frame(maxWidth: .infinity).padding(.vertical, 40)
    }

    @ViewBuilder
    private func row(_ site: DestinationSeen) -> some View {
        let live = site.isLive(now: now)
        let blocked = site.blocked || store.isBlocked(domain: nil, host: site.name, ip: site.id)
        HStack(spacing: 9) {
            Circle()
                .fill(live ? Theme.palette[0] : Theme.idleWire)
                .frame(width: 6, height: 6)
            FaviconView(domain: site.id, favicon: nil, size: 16)
            VStack(alignment: .leading, spacing: 1) {
                Text(site.name)
                    .font(TypeStyle.mono(11)).foregroundStyle(Theme.ink)
                    .lineLimit(1).truncationMode(.middle)
                HStack(spacing: 5) {
                    Text(site.lastApp).font(TypeStyle.caption(9)).foregroundStyle(Theme.inkSecondary).lineLimit(1)
                    if site.band.wantsAttention {
                        Text(site.band.rawValue).font(TypeStyle.label(8)).foregroundStyle(Theme.band(site.band))
                    }
                }
            }
            Spacer(minLength: 4)
            Text(ByteFormat.tight(site.bytes)).font(TypeStyle.mono(9)).foregroundStyle(Theme.inkTertiary)
            blockButton(site, blocked: blocked)
        }
        .padding(.horizontal, 10).padding(.vertical, 8)
        .background(RoundedRectangle(cornerRadius: 9).fill(Color.white.opacity(0.03)))
        .overlay(
            RoundedRectangle(cornerRadius: 9)
                .strokeBorder(blocked ? Theme.band(.loud).opacity(0.4) : Color.white.opacity(0.05), lineWidth: 0.5)
        )
    }

    private func blockButton(_ site: DestinationSeen, blocked: Bool) -> some View {
        Button {
            if blocked {
                for r in store.rules where r.match.lowercased() == site.name.lowercased() || r.match == site.id {
                    store.deleteRule(id: r.id)
                }
            } else {
                // A named destination blocks by domain (covers its subdomains);
                // a bare address blocks by dest.
                if site.name == site.id, site.name.contains(where: { $0 == ":" }) || site.name.first?.isNumber == true {
                    store.addRule(scope: "dest", match: site.id, note: "from all-sites")
                } else {
                    store.addRule(scope: "domain", match: site.name, note: "from all-sites")
                }
            }
        } label: {
            Image(systemName: blocked ? "hand.raised.fill" : "hand.raised")
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(blocked ? Theme.band(.loud) : Theme.inkTertiary)
        }
        .buttonStyle(.plain)
        .help(blocked ? "Remove block" : "Block this destination")
    }
}

/// Shared collapse chevron for the side panels.
func collapseButton(_ action: @escaping () -> Void) -> some View {
    Button(action: action) {
        Image(systemName: "chevron.left")
            .font(.system(size: 10, weight: .semibold))
            .foregroundStyle(Theme.inkSecondary)
            .frame(width: 24, height: 24)
            .glassCapsule(rimOpacity: 0.2, shadowRadius: 3, shadowY: 1)
    }
    .buttonStyle(.plain)
}
