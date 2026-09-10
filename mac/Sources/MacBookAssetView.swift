import AppKit
import SwiftUI

enum BundleResources {
    static var macbookUSDZ: URL? {
        Bundle.main.url(forResource: "macbook-pro", withExtension: "usdz")
    }

    static var macbookHero: NSImage? {
        guard let url = Bundle.main.url(forResource: "macbook-hero", withExtension: "png") else { return nil }
        return NSImage(contentsOf: url)
    }
}

/// The machine at the centre of the canvas.
///
/// Two previous attempts at this rendered nothing, for two different reasons,
/// and both are worth recording so nobody tries them again:
///
///   - `MacBook3DView` wraps `SCNView`. AppKit views are composited outside
///     SwiftUI's transforms, so inside the pan/zoom viewport it drew nothing.
///   - `MacBookView` builds the shape from stacked `rotation3DEffect`s with
///     perspective, including a lid rotated past vertical. Nested inside the
///     viewport's own `scaleEffect` that collapses to nothing visible.
///
/// So this is drawn flat, front-on, with plain shapes and no 3D transform
/// anywhere. It composites correctly under any scale because there is nothing
/// clever in it - and a flat mark suits the rest of the design better than a
/// faux-perspective one anyway. The 3D model still earns its keep on the splash
/// screen, where no transform sits above it.
struct MacBookAssetView: View {
    var width: CGFloat = 320
    var zoom: CGFloat = 1

    private var w: CGFloat { width * zoom }

    var body: some View {
        ZStack {
            // A soft pool of light so the machine reads as the anchor the
            // cables radiate from, rather than another node.
            Circle()
                .fill(
                    RadialGradient(
                        colors: [Color.white.opacity(0.05), .clear],
                        center: .center, startRadius: 0, endRadius: w * 0.72
                    )
                )
                .frame(width: w * 1.5, height: w * 1.5)

            VStack(spacing: 0) {
                lid
                base
            }
        }
        .frame(width: w * 1.1, height: w * 0.78)
        .shadow(color: Color.black.opacity(0.6), radius: w * 0.07, y: w * 0.03)
    }

    private var lid: some View {
        RoundedRectangle(cornerRadius: w * 0.035, style: .continuous)
            .fill(
                LinearGradient(
                    colors: [Theme.starlight, Theme.starlightDeep],
                    startPoint: .top, endPoint: .bottom
                )
            )
            .frame(width: w * 0.84, height: w * 0.55)
            .overlay(screen)
            .overlay(
                RoundedRectangle(cornerRadius: w * 0.035, style: .continuous)
                    .strokeBorder(Color.white.opacity(0.35), lineWidth: 0.6)
            )
    }

    private var screen: some View {
        RoundedRectangle(cornerRadius: w * 0.02, style: .continuous)
            .fill(Theme.screenGlass)
            .overlay(
                // A faint sheen across the glass; two flat colours read as a
                // switched-off rectangle rather than a screen.
                LinearGradient(
                    colors: [Color.white.opacity(0.07), .clear, Color.white.opacity(0.03)],
                    startPoint: .topLeading, endPoint: .bottomTrailing
                )
                .clipShape(RoundedRectangle(cornerRadius: w * 0.02, style: .continuous))
            )
            .overlay(alignment: .top) {
                Capsule()
                    .fill(Color.black.opacity(0.85))
                    .frame(width: w * 0.09, height: w * 0.014)
                    .padding(.top, w * 0.013)
            }
            .padding(w * 0.022)
    }

    /// Slightly wider than the lid and tapering outward, which is what makes a
    /// flat drawing read as a laptop rather than a picture frame.
    private var base: some View {
        MacBookBase()
            .fill(
                LinearGradient(
                    colors: [Theme.starlightDeep, Theme.starlight.opacity(0.82)],
                    startPoint: .top, endPoint: .bottom
                )
            )
            .frame(width: w, height: w * 0.045)
            .overlay(alignment: .top) {
                // The hinge notch.
                Capsule()
                    .fill(Color.black.opacity(0.28))
                    .frame(width: w * 0.14, height: w * 0.008)
            }
    }
}

private struct MacBookBase: Shape {
    func path(in rect: CGRect) -> Path {
        let inset = rect.width * 0.06
        let r = rect.height * 0.45
        var p = Path()
        p.move(to: CGPoint(x: rect.minX + inset, y: rect.minY))
        p.addLine(to: CGPoint(x: rect.maxX - inset, y: rect.minY))
        p.addLine(to: CGPoint(x: rect.maxX - r, y: rect.maxY))
        p.addQuadCurve(
            to: CGPoint(x: rect.maxX - r - r, y: rect.maxY),
            control: CGPoint(x: rect.maxX - r, y: rect.maxY)
        )
        p.addLine(to: CGPoint(x: rect.minX + r, y: rect.maxY))
        p.closeSubpath()
        return p
    }
}
