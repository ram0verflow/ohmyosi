import AppKit
import SwiftUI

@MainActor
final class IconCache: ObservableObject {
    @Published private(set) var tick = 0

    private var remote: [String: NSImage] = [:]
    private var local: [String: NSImage] = [:]
    private var loading: Set<String> = []

    func image(url: URL?) -> NSImage? {
        guard let url else { return nil }
        return remote[url.absoluteString]
    }

    func image(path: String?) -> NSImage? {
        guard let path, !path.isEmpty else { return nil }
        if let hit = local[path] { return hit }
        let img = NSWorkspace.shared.icon(forFile: path)
        local[path] = img
        return img
    }

    func preload(urls: [URL], paths: [String]) {
        for path in paths where !path.isEmpty { _ = image(path: path) }
        for url in urls {
            fetch(url)
        }
    }

    private func fetch(_ url: URL) {
        let key = url.absoluteString
        guard remote[key] == nil, !loading.contains(key) else { return }
        loading.insert(key)
        Task {
            defer { loading.remove(key) }
            guard let (data, _) = try? await URLSession.shared.data(from: url),
                  let img = NSImage(data: data) else { return }
            remote[key] = img
            tick &+= 1
        }
    }
}

struct AppIconView: View {
    @EnvironmentObject private var icons: IconCache
    let url: URL?
    let localPath: String?
    var symbol: String = "app.fill"
    var size: CGFloat = 44
    var accentHue: Double = 0.58

    var body: some View {
        let _ = icons.tick
        Group {
            if let img = icons.image(url: url) ?? icons.image(path: localPath) {
                Image(nsImage: img)
                    .resizable()
                    .interpolation(.high)
                    .aspectRatio(contentMode: .fit)
            } else if url != nil {
                RoundedRectangle(cornerRadius: size * 0.22, style: .continuous)
                    .fill(Theme.card)
                    .overlay { ProgressView().controlSize(.small) }
            } else {
                Image(systemName: symbol)
                    .font(.system(size: size * 0.36, weight: .regular))
                    .foregroundStyle(Theme.inkSecondary)
            }
        }
        .padding(size * 0.1)
        .frame(width: size, height: size)
        .background(Theme.card, in: RoundedRectangle(cornerRadius: size * 0.22, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: size * 0.22, style: .continuous)
                .strokeBorder(Theme.cardBorder, lineWidth: 0.5)
        )
        .shadow(color: Theme.shadow, radius: hoveredShadow ? 14 : 8, y: hoveredShadow ? 6 : 3)
        .onAppear {
            icons.preload(urls: url.map { [$0] } ?? [], paths: localPath.map { [$0] } ?? [])
        }
    }

    private var hoveredShadow: Bool { false }
}
