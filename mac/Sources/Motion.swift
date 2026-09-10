import SwiftUI

enum Motion {
    static let snap = Animation.spring(response: 0.38, dampingFraction: 0.78)
    static let smooth = Animation.spring(response: 0.55, dampingFraction: 0.86)
    static let open = Animation.spring(response: 0.95, dampingFraction: 0.72)
    static let pop = Animation.spring(response: 0.32, dampingFraction: 0.68)
    static let breathe = Animation.easeInOut(duration: 2.4).repeatForever(autoreverses: true)
    /// Hover feedback: fast enough to feel attached to the cursor, slow enough
    /// not to flicker when it crosses a node edge.
    static let hover = Animation.spring(response: 0.24, dampingFraction: 0.72)
    /// Focus changes, which move a lot of pixels at once, so no bounce.
    static let focus = Animation.easeInOut(duration: 0.28)
}

/// When each cable was first seen, so it can draw itself in.
///
/// The scene is rebuilt every frame, so "is this edge new" cannot be answered
/// from the scene alone - it needs somewhere to remember. Keyed by edge id,
/// which is stable across rebuilds.
@MainActor
enum EdgeBirth {
    private static var born: [String: Date] = [:]

    static func progress(_ id: String, now: Date, duration: Double) -> Double {
        if let t = born[id] {
            return min(1, max(0, now.timeIntervalSince(t) / duration))
        }
        born[id] = now
        return 0
    }

    /// Forget cables that no longer exist, so a long session does not
    /// accumulate every edge it has ever drawn.
    static func prune(live: Set<String>) {
        guard born.count > live.count * 2 else { return }
        born = born.filter { live.contains($0.key) }
    }
}

struct StaggerAppear: ViewModifier {
    let index: Int
    @State private var visible = false

    func body(content: Content) -> some View {
        content
            .scaleEffect(visible ? 1 : 0.4)
            .opacity(visible ? 1 : 0)
            .onAppear {
                withAnimation(Motion.pop.delay(Double(index) * 0.06)) {
                    visible = true
                }
            }
    }
}

struct FloatPulse: ViewModifier {
    func body(content: Content) -> some View {
        TimelineView(.animation(minimumInterval: 1.0 / 30.0)) { ctx in
            let y = sin(ctx.date.timeIntervalSinceReferenceDate * 1.4) * 3.5
            content.offset(y: y)
        }
    }
}

extension View {
    func staggerAppear(index: Int) -> some View {
        modifier(StaggerAppear(index: index))
    }

    func floatPulse() -> some View {
        modifier(FloatPulse())
    }
}
