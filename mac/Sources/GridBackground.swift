import SwiftUI

/// Subtle engineering grid — not decorative.
struct GridBackground: View {
    var spacing: CGFloat = 32

    var body: some View {
        Canvas { context, size in
            var path = Path()
            var x: CGFloat = 0
            while x <= size.width {
                path.move(to: CGPoint(x: x, y: 0))
                path.addLine(to: CGPoint(x: x, y: size.height))
                x += spacing
            }
            var y: CGFloat = 0
            while y <= size.height {
                path.move(to: CGPoint(x: 0, y: y))
                path.addLine(to: CGPoint(x: size.width, y: y))
                y += spacing
            }
            context.stroke(path, with: .color(Theme.gridLine), lineWidth: 0.5)
        }
        // No background of its own: the window owns the ground, so the canvas
        // has no edge to give itself away.
    }
}
