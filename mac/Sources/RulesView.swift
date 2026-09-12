import SwiftUI

/// The rules panel. Two things live here: imported **category** blocklists,
/// which collapse to a single row each (an adult list is thousands of domains,
/// not thousands of rows), and the individual rules you made by hand. Tapping a
/// category opens its own searchable list.
struct RulesView: View {
    @EnvironmentObject private var store: MonitorStore
    var onCollapse: () -> Void

    @State private var scope = "domain"
    @State private var match = ""
    @State private var action = "block"
    /// When set, we are inside one category's domain list.
    @State private var openCategory: (note: String, title: String)?

    private let scopes = ["domain", "app", "dest", "port"]

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if let cat = openCategory {
                CategoryListView(note: cat.note, title: cat.title, onBack: { openCategory = nil })
            } else {
                overview
            }
        }
        .frame(width: RailMetrics.panelWidth)
        .frame(maxHeight: .infinity)
        .glassCard(cornerRadius: 18, material: .regularMaterial, rimOpacity: 0.24, shadowRadius: 30, shadowY: 0)
    }

    private var overview: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            addForm
            Divider().overlay(Theme.cardBorder)
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 6) {
                    ForEach(store.ruleGroups, id: \.note) { group in
                        categoryRow(group)
                    }
                    if !store.manualRules.isEmpty {
                        Text("INDIVIDUAL RULES")
                            .font(TypeStyle.label(8)).foregroundStyle(Theme.inkTertiary)
                            .padding(.top, 8).padding(.leading, 2)
                    }
                    ForEach(store.manualRules) { rule in row(rule) }
                    if store.rules.isEmpty { empty }
                }
                .padding(12)
            }
        }
    }

    private var header: some View {
        HStack(spacing: 8) {
            Image(systemName: "hand.raised").font(.system(size: 12, weight: .semibold)).foregroundStyle(Theme.inkSecondary)
            Text("Rules").font(TypeStyle.title(13)).foregroundStyle(Theme.ink)
            InfoButton(text: """
            Allow or block by **app**, **domain**, **dest** (ip / ip:port) or **port**. An allow always beats a block, so you can block broadly and carve out an exception.

            Imported category lists collapse to one row — open it to search its domains. Blocking is **observe-only** until you turn on enforcement in Controls; domains block via /etc/hosts, an app or single connection via pf on its exact 5-tuple.
            """)
            Spacer(minLength: 0)
            collapseButton(onCollapse)
        }
        .padding(14)
    }

    private var addForm: some View {
        VStack(spacing: 8) {
            HStack(spacing: 6) {
                Picker("", selection: $scope) {
                    ForEach(scopes, id: \.self) { Text($0).tag($0) }
                }
                .labelsHidden().frame(width: 92)
                TextField(placeholder, text: $match)
                    .textFieldStyle(.plain).font(TypeStyle.mono(11)).foregroundStyle(Theme.ink)
                    .padding(.horizontal, 8).padding(.vertical, 6)
                    .background(RoundedRectangle(cornerRadius: 8).fill(Color.white.opacity(0.05)))
                    .onSubmit(add)
            }
            HStack(spacing: 8) {
                Picker("", selection: $action) {
                    Text("block").tag("block")
                    Text("allow").tag("allow")
                }
                .pickerStyle(.segmented).labelsHidden().frame(width: 140)
                Spacer()
                Button(action: add) {
                    Text("Add rule").font(TypeStyle.label(10)).foregroundStyle(Theme.ink)
                        .padding(.horizontal, 10).padding(.vertical, 5)
                        .glassCapsule(rimOpacity: 0.35, shadowRadius: 4, shadowY: 1)
                }
                .buttonStyle(.plain)
                .disabled(!store.canControl || match.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
        .padding(.horizontal, 12).padding(.bottom, 12)
    }

    private var placeholder: String {
        switch scope {
        case "app": return "Spotify"
        case "domain": return "doubleclick.net"
        case "dest": return "1.2.3.4 or 1.2.3.4:443"
        case "port": return "23"
        default: return "value"
        }
    }

    private func add() {
        let m = match.trimmingCharacters(in: .whitespaces)
        guard !m.isEmpty else { return }
        store.addRule(scope: scope, match: m, action: action, note: "added in app")
        match = ""
    }

    private var empty: some View {
        VStack(spacing: 6) {
            Image(systemName: "hand.raised").font(.system(size: 20, weight: .light)).foregroundStyle(Theme.inkTertiary)
            Text("No rules yet").font(TypeStyle.body(12)).foregroundStyle(Theme.inkSecondary)
            Text("Block an app, a domain, or a destination — or import a category from Controls.")
                .font(TypeStyle.caption(10)).foregroundStyle(Theme.inkTertiary)
                .multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity).padding(.horizontal, 24).padding(.vertical, 28)
    }

    private func categoryRow(_ group: (note: String, title: String, rules: [BlockRule])) -> some View {
        Button { openCategory = (group.note, group.title) } label: {
            HStack(spacing: 8) {
                Image(systemName: "list.bullet.rectangle.fill")
                    .font(.system(size: 12)).foregroundStyle(Theme.band(.loud))
                VStack(alignment: .leading, spacing: 1) {
                    Text(group.title).font(TypeStyle.body(12)).foregroundStyle(Theme.ink)
                    Text("\(group.rules.count) domains").font(TypeStyle.caption(9)).foregroundStyle(Theme.inkTertiary)
                }
                Spacer(minLength: 4)
                Image(systemName: "chevron.right").font(.system(size: 9, weight: .semibold)).foregroundStyle(Theme.inkTertiary)
            }
            .padding(.horizontal, 10).padding(.vertical, 9)
            .background(RoundedRectangle(cornerRadius: 9).fill(Color.white.opacity(0.04)))
            .overlay(RoundedRectangle(cornerRadius: 9).strokeBorder(Theme.band(.loud).opacity(0.25), lineWidth: 0.5))
        }
        .buttonStyle(.plain)
    }

    private func row(_ rule: BlockRule) -> some View {
        let color = rule.isBlock ? Theme.band(.loud) : Theme.palette[5]
        return HStack(spacing: 8) {
            Text(rule.isBlock ? "BLOCK" : "ALLOW")
                .font(TypeStyle.label(8)).foregroundStyle(color)
                .padding(.horizontal, 5).padding(.vertical, 2)
                .background(Capsule().fill(color.opacity(0.14)))
            VStack(alignment: .leading, spacing: 1) {
                Text(rule.match).font(TypeStyle.mono(11)).foregroundStyle(Theme.ink).lineLimit(1).truncationMode(.middle)
                Text(rule.scope).font(TypeStyle.caption(9)).foregroundStyle(Theme.inkTertiary)
            }
            Spacer(minLength: 4)
            Button { store.deleteRule(id: rule.id) } label: {
                Image(systemName: "trash").font(.system(size: 11)).foregroundStyle(Theme.inkTertiary)
            }
            .buttonStyle(.plain)
            .disabled(!store.canControl)
            .help("Remove rule")
        }
        .padding(.horizontal, 10).padding(.vertical, 8)
        .background(RoundedRectangle(cornerRadius: 9).fill(Color.white.opacity(0.03)))
    }
}

/// The searchable domain list for one imported category, kept out of the main
/// rules view so a big list never buries the handful of rules you made yourself.
struct CategoryListView: View {
    @EnvironmentObject private var store: MonitorStore
    let note: String
    let title: String
    var onBack: () -> Void

    @State private var query = ""

    private var domains: [BlockRule] {
        let all = store.rules.filter { $0.note == note }
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        return (q.isEmpty ? all : all.filter { $0.match.lowercased().contains(q) })
            .sorted { $0.match < $1.match }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 8) {
                Button(action: onBack) {
                    Image(systemName: "chevron.left").font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(Theme.inkSecondary).frame(width: 24, height: 24)
                        .glassCapsule(rimOpacity: 0.2, shadowRadius: 3, shadowY: 1)
                }
                .buttonStyle(.plain)
                Text(title).font(TypeStyle.title(13)).foregroundStyle(Theme.ink)
                Text("\(store.rules.filter { $0.note == note }.count)")
                    .font(TypeStyle.mono(10)).foregroundStyle(Theme.inkSecondary)
                Spacer(minLength: 0)
                Button {
                    store.deleteRuleGroup(note: note)
                    onBack()
                } label: {
                    Text("Remove all").font(TypeStyle.label(9)).foregroundStyle(Theme.band(.loud))
                        .padding(.horizontal, 8).padding(.vertical, 4)
                        .glassCapsule(rimOpacity: 0.3, shadowRadius: 3, shadowY: 1)
                }
                .buttonStyle(.plain)
                .disabled(!store.canControl)
                .help("Remove this entire category")
            }
            .padding(14)

            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass").font(.system(size: 10)).foregroundStyle(Theme.inkTertiary)
                TextField("search this list", text: $query)
                    .textFieldStyle(.plain).font(TypeStyle.mono(11)).foregroundStyle(Theme.ink)
            }
            .padding(.horizontal, 10).padding(.vertical, 7)
            .background(RoundedRectangle(cornerRadius: 9).fill(Color.white.opacity(0.05)))
            .padding(.horizontal, 12).padding(.bottom, 8)

            ScrollView {
                LazyVStack(alignment: .leading, spacing: 4) {
                    ForEach(domains.prefix(500)) { r in
                        HStack(spacing: 8) {
                            FaviconView(domain: r.match, favicon: nil, size: 14)
                            Text(r.match).font(TypeStyle.mono(11)).foregroundStyle(Theme.ink)
                                .lineLimit(1).truncationMode(.middle)
                            Spacer(minLength: 4)
                            Button { store.deleteRule(id: r.id) } label: {
                                Image(systemName: "xmark.circle").font(.system(size: 10)).foregroundStyle(Theme.inkTertiary)
                            }
                            .buttonStyle(.plain)
                            .disabled(!store.canControl)
                            .help("Remove just this domain")
                        }
                        .padding(.horizontal, 10).padding(.vertical, 6)
                        .background(RoundedRectangle(cornerRadius: 8).fill(Color.white.opacity(0.03)))
                    }
                    if domains.count > 500 {
                        Text("+\(domains.count - 500) more — search to narrow")
                            .font(TypeStyle.caption(10)).foregroundStyle(Theme.inkTertiary).padding(.top, 4)
                    }
                }
                .padding(12)
            }
        }
    }
}
