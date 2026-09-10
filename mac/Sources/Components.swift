import SwiftUI

/// A small favicon for a destination. Prefers the daemon-fetched icon when
/// present, otherwise resolves one from the domain through a favicon service -
/// which works for any site, adult ones included, without this machine
/// connecting to the site itself. Falls back to a globe glyph.
struct FaviconView: View {
    @EnvironmentObject private var icons: IconCache
    let domain: String?
    let favicon: String?
    var size: CGFloat = 15

    private var url: URL? {
        if let f = favicon, !f.isEmpty {
            return GraphLayout.daemonBase.appendingPathComponent("favicons/\(f)")
        }
        guard let d = domain, !d.isEmpty else { return nil }
        return ProviderLogos.faviconURL(forDomain: d)
    }

    var body: some View {
        let _ = icons.tick
        Group {
            if let url, let img = icons.image(url: url) {
                Image(nsImage: img).resizable().interpolation(.high).aspectRatio(contentMode: .fit)
                    .clipShape(RoundedRectangle(cornerRadius: 3, style: .continuous))
            } else {
                Image(systemName: "globe")
                    .font(.system(size: size * 0.72, weight: .regular))
                    .foregroundStyle(Theme.inkTertiary)
            }
        }
        .frame(width: size, height: size)
        .onAppear { if let url { icons.preload(urls: [url], paths: []) } }
    }
}

/// An "i" that reveals a short explanation on click. This is how the panels stay
/// icon-first: the chrome carries no instructional text, and anything that needs
/// describing is one tap away rather than always on screen.
struct InfoButton: View {
    let text: String
    var edge: Edge = .bottom
    @State private var show = false

    var body: some View {
        Button { show.toggle() } label: {
            Image(systemName: "info.circle")
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(Theme.inkTertiary)
        }
        .buttonStyle(.plain)
        .help("What is this?")
        .popover(isPresented: $show, arrowEdge: edge) {
            Text(.init(text))
                .font(TypeStyle.body(11))
                .foregroundStyle(Theme.ink)
                .frame(width: 250, alignment: .leading)
                .fixedSize(horizontal: false, vertical: true)
                .padding(14)
                .background(Theme.card)
        }
    }
}
