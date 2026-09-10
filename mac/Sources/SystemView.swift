import SwiftUI

/// The controls panel: everything ohmyosi can *do*, not just show. Enforcement,
/// category blocklists, and the two identifiers the machine broadcasts. Each
/// action is carried out by the daemon (which has root); the app just asks. When
/// the daemon is not running as root, the actions that change the system are
/// shown disabled with the reason, rather than failing silently.
struct SystemView: View {
    @EnvironmentObject private var store: MonitorStore
    var onCollapse: () -> Void

    @State private var iface = "en0"
    @State private var hostname = ""

    private var ifaceOptions: [String] { store.interfaces.isEmpty ? ["en0"] : store.interfaces }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    enforcementSection
                    blocklistSection
                    identitySection
                    if let msg = store.actionMessage {
                        Text(msg)
                            .font(TypeStyle.caption(10))
                            .foregroundStyle(Theme.inkSecondary)
                            .fixedSize(horizontal: false, vertical: true)
                            .padding(.top, 2)
                    }
                }
                .padding(14)
            }
        }
        .frame(width: RailMetrics.panelWidth)
        .frame(maxHeight: .infinity)
        .glassCard(cornerRadius: 18, material: .regularMaterial, rimOpacity: 0.24, shadowRadius: 30, shadowY: 0)
        .onAppear {
            store.loadStatus()
            if let first = store.interfaces.first { iface = first }
            if hostname.isEmpty { hostname = store.host?.hostname.components(separatedBy: ".").first ?? "" }
        }
    }

    private var header: some View {
        HStack(spacing: 8) {
            Image(systemName: "gearshape").font(.system(size: 12, weight: .semibold)).foregroundStyle(Theme.inkSecondary)
            Text("Controls").font(TypeStyle.title(13)).foregroundStyle(Theme.ink)
            InfoButton(text: """
            Everything the tool can **do**, driven from here — no terminal needed.

            **Enforcement** turns block rules from "what they'd do" into actually blocking, via pf and /etc/hosts. **Blocklists** import maintained category lists as rules. **Identity** changes the MAC and hostname this machine broadcasts. Actions that change the system need the daemon running as root.
            """)
            Spacer(minLength: 0)
            collapseButton(onCollapse)
        }
        .padding(14)
    }

    // MARK: Enforcement

    private var enforcementSection: some View {
        section("Enforcement", icon: "shield.lefthalf.filled") {
            HStack(spacing: 10) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(store.enforcing ? "Blocking is on" : "Observe only")
                        .font(TypeStyle.body(12))
                        .foregroundStyle(store.enforcing ? Theme.band(.loud) : Theme.ink)
                    Text(store.enforcing
                         ? "Matching flows are blocked via pf and /etc/hosts."
                         : "Rules show what they would do, but nothing is blocked.")
                        .font(TypeStyle.caption(9)).foregroundStyle(Theme.inkTertiary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 6)
                Toggle("", isOn: Binding(get: { store.enforcing }, set: { store.setEnforce($0) }))
                    .labelsHidden()
                    .disabled(!store.isRoot)
            }
            if !store.isRoot {
                rootNote
            }
        }
    }

    // MARK: Blocklists

    private var blocklistSection: some View {
        section("Category blocklists", icon: "list.bullet.rectangle") {
            Text("Import a maintained list as domain rules. Turn on enforcement to apply.")
                .font(TypeStyle.caption(9)).foregroundStyle(Theme.inkTertiary)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 6) {
                categoryButton("Adult sites", "adult", "eye.slash")
                categoryButton("Ads & trackers", "ads", "hand.raised")
            }
            HStack(spacing: 6) {
                categoryButton("Gambling", "gambling", "dollarsign.circle")
                categoryButton("Social", "social", "bubble.left.and.bubble.right")
            }
        }
    }

    private func categoryButton(_ label: String, _ src: String, _ icon: String) -> some View {
        Button { store.importBlocklist(src) } label: {
            HStack(spacing: 5) {
                Image(systemName: icon).font(.system(size: 10, weight: .medium))
                Text(label).font(TypeStyle.label(10))
            }
            .foregroundStyle(Theme.ink)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 7)
            .glassCapsule(rimOpacity: 0.28, shadowRadius: 4, shadowY: 1)
        }
        .buttonStyle(.plain)
        .help("Import the \(label) blocklist")
    }

    // MARK: Identity

    private var identitySection: some View {
        section("Network identity", icon: "wifi") {
            HStack(spacing: 6) {
                Picker("", selection: $iface) {
                    ForEach(ifaceOptions, id: \.self) { Text($0).tag($0) }
                }
                .labelsHidden().frame(width: 90).disabled(!store.isRoot)
                Button { store.spoofMAC(iface) } label: {
                    Label("Randomize MAC", systemImage: "shuffle").font(TypeStyle.label(10))
                        .foregroundStyle(Theme.ink)
                        .frame(maxWidth: .infinity).padding(.vertical, 7)
                        .glassCapsule(rimOpacity: 0.28, shadowRadius: 4, shadowY: 1)
                }
                .buttonStyle(.plain).disabled(!store.isRoot)
            }
            HStack(spacing: 6) {
                TextField("hostname", text: $hostname)
                    .textFieldStyle(.plain).font(TypeStyle.mono(11)).foregroundStyle(Theme.ink)
                    .padding(.horizontal, 8).padding(.vertical, 6)
                    .background(RoundedRectangle(cornerRadius: 8).fill(Color.white.opacity(0.05)))
                    .disabled(!store.isRoot)
                Button { store.setHostname(hostname) } label: {
                    Text("Set").font(TypeStyle.label(10)).foregroundStyle(Theme.ink)
                        .padding(.horizontal, 12).padding(.vertical, 7)
                        .glassCapsule(rimOpacity: 0.28, shadowRadius: 4, shadowY: 1)
                }
                .buttonStyle(.plain)
                .disabled(!store.isRoot || hostname.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            if !store.isRoot {
                rootNote
            }
        }
    }

    private var rootNote: some View {
        Text("Run the daemon with sudo to change the system.")
            .font(TypeStyle.caption(9)).foregroundStyle(Theme.band(.notable))
    }

    // MARK: Section chrome

    private func section<Content: View>(_ title: String, icon: String, @ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                Image(systemName: icon).font(.system(size: 10, weight: .semibold)).foregroundStyle(Theme.inkSecondary)
                Text(title.uppercased()).font(TypeStyle.label(9)).foregroundStyle(Theme.inkSecondary)
            }
            content()
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 12).fill(Color.white.opacity(0.03)))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Color.white.opacity(0.05), lineWidth: 0.5))
    }
}
