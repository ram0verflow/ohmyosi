import SwiftUI

/// Glass surfaces.
///
/// Apple's current language is Liquid Glass, whose `glassEffect` modifier is
/// macOS 26 API; this package targets macOS 14, so the effect is assembled by
/// hand from the parts that actually make glass read as glass:
///
///   1. a real backdrop blur (`Material`, not a translucent fill - a flat
///      colour at 20% opacity is the tell that separates fake glass from real);
///   2. a specular rim, brightest along the top edge, because glass catches
///      light where it curves away from you;
///   3. a soft inner sheen so the surface has a gradient rather than one tone;
///   4. a wide, low-opacity drop shadow to lift it off the ground.
///
/// Keeping all of that here means swapping in the real API later is a change in
/// one file rather than forty call sites.
struct GlassSurface<S: InsettableShape>: View {
    var shape: S
    var material: Material = .ultraThinMaterial
    var tint: Color = .white
    var rimOpacity: Double = 0.30
    var shadowRadius: CGFloat = 18
    var shadowY: CGFloat = 8

    var body: some View {
        shape
            .fill(material)
            .overlay(sheen)
            .overlay(rim)
            .shadow(color: Color.black.opacity(0.45), radius: shadowRadius, y: shadowY)
    }

    /// A vertical sheen: bright at the top, gone by a third of the way down.
    private var sheen: some View {
        shape.fill(
            LinearGradient(
                stops: [
                    .init(color: tint.opacity(0.10), location: 0),
                    .init(color: tint.opacity(0.02), location: 0.35),
                    .init(color: .clear, location: 1),
                ],
                startPoint: .top, endPoint: .bottom
            )
        )
    }

    /// The specular edge. A single flat stroke looks like a border; a gradient
    /// stroke that fades toward the bottom looks like a lit edge.
    private var rim: some View {
        shape.strokeBorder(
            LinearGradient(
                colors: [
                    tint.opacity(rimOpacity),
                    tint.opacity(rimOpacity * 0.28),
                    tint.opacity(rimOpacity * 0.10),
                ],
                startPoint: .top, endPoint: .bottom
            ),
            lineWidth: 0.8
        )
    }
}

extension View {
    /// Glass in a rounded rectangle.
    func glassCard(
        cornerRadius: CGFloat,
        material: Material = .ultraThinMaterial,
        rimOpacity: Double = 0.30,
        shadowRadius: CGFloat = 18,
        shadowY: CGFloat = 8
    ) -> some View {
        background(
            GlassSurface(
                shape: RoundedRectangle(cornerRadius: cornerRadius, style: .continuous),
                material: material, rimOpacity: rimOpacity,
                shadowRadius: shadowRadius, shadowY: shadowY
            )
        )
    }

    /// Glass in a capsule, for pills and toolbars.
    func glassCapsule(
        material: Material = .ultraThinMaterial,
        rimOpacity: Double = 0.30,
        shadowRadius: CGFloat = 18,
        shadowY: CGFloat = 8
    ) -> some View {
        background(
            GlassSurface(
                shape: Capsule(), material: material, rimOpacity: rimOpacity,
                shadowRadius: shadowRadius, shadowY: shadowY
            )
        )
    }
}
