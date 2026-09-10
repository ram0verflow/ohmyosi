import SwiftUI

/// Dark, restrained, high-contrast. The reference points are Raycast and
/// CleanMyMac: depth comes from a near-black ground, one soft shadow and
/// controlled colour, never from chrome or from more colours.
///
/// The previous palette derived a hue per node from a hash, which produced
/// thirty saturated colours with no hierarchy - every edge shouting equally
/// loudly is the same as none of them shouting. Colour now does exactly one
/// job: it tells you which application a cable belongs to. Destinations are
/// deliberately neutral, because "which app is this" is the question the eye
/// should be able to answer without reading anything.
enum Theme {
    static let canvas = Color(red: 0.043, green: 0.051, blue: 0.063)
    static let canvasDeep = Color(red: 0.024, green: 0.031, blue: 0.043)
    static let gridLine = Color(red: 1, green: 1, blue: 1).opacity(0.028)
    static let gridDot = Color(red: 1, green: 1, blue: 1).opacity(0.05)

    static let ink = Color(red: 0.902, green: 0.918, blue: 0.945)
    static let inkSecondary = Color(red: 0.545, green: 0.580, blue: 0.639)
    static let inkTertiary = Color(red: 0.357, green: 0.388, blue: 0.443)

    static let card = Color(red: 0.086, green: 0.098, blue: 0.118)
    static let cardRaised = Color(red: 0.118, green: 0.133, blue: 0.157)
    static let cardBorder = Color.white.opacity(0.08)
    static let shadow = Color.black.opacity(0.55)

    // The machine itself. Kept light so it reads as the one physical object on
    // a dark canvas - it is the anchor everything else radiates from.
    static let starlight = Color(red: 0.851, green: 0.859, blue: 0.875)
    static let starlightDeep = Color(red: 0.639, green: 0.651, blue: 0.678)
    static let keyboard = Color(red: 0.129, green: 0.141, blue: 0.161)
    static let screenGlass = Color(red: 0.031, green: 0.039, blue: 0.051)
    static let machineBody = starlight
    static let machineScreen = screenGlass

    /// Eight accents, hand-picked to sit on a near-black ground at similar
    /// perceived weight. Same count as a good editor theme, for the same
    /// reason: past eight, colour stops identifying and starts decorating.
    static let palette: [Color] = [
        Color(red: 0.176, green: 0.831, blue: 0.749), // teal
        Color(red: 0.506, green: 0.549, blue: 0.973), // indigo
        Color(red: 0.984, green: 0.749, blue: 0.141), // amber
        Color(red: 0.984, green: 0.443, blue: 0.522), // rose
        Color(red: 0.220, green: 0.741, blue: 0.973), // sky
        Color(red: 0.639, green: 0.906, blue: 0.208), // lime
        Color(red: 0.753, green: 0.518, blue: 0.988), // violet
        Color(red: 0.984, green: 0.573, blue: 0.235), // orange
    ]

    /// Buckets a stable hash into the ramp. Collisions are accepted on
    /// purpose: an app keeping the same colour across restarts matters more
    /// than every app having a unique one.
    static func accent(_ seed: Double) -> Color {
        let i = Int((seed * 977).rounded(.down))
        return palette[((i % palette.count) + palette.count) % palette.count]
    }

    /// Destinations echo the app that talks to them. Darkened rather than made
    /// transparent: a translucent cable picks up whatever is behind it, which
    /// is why the old ones looked washed out over the grid.
    static func destinationTint(_ seed: Double) -> Color {
        accent(seed).opacity(1)
    }

    /// Suspicion bands. One warm ramp from calm to loud, kept off the app
    /// palette so "this wants attention" never reads as just another app colour.
    /// Amber for notable, orange for unusual, red for loud - the same grammar a
    /// person already reads on a dashboard.
    static func band(_ b: SuspicionBand) -> Color {
        switch b {
        case .quiet: return inkTertiary
        case .notable: return Color(red: 0.984, green: 0.749, blue: 0.141)
        case .unusual: return Color(red: 0.984, green: 0.573, blue: 0.235)
        case .loud: return Color(red: 0.965, green: 0.310, blue: 0.310)
        }
    }

    /// An open connection with nothing moving through it.
    static let idleWire = Color(red: 0.267, green: 0.298, blue: 0.353)

    static let relay = Color(red: 0.435, green: 0.475, blue: 0.541)

    /// Cable width. Deliberately narrow: at a hundred edges, thick strokes
    /// are what turned the last version into a ball of wool.
    static func lineWidth(bytes: UInt64, maxBytes: UInt64, style: GraphEdge.Style) -> CGFloat {
        let rank = maxBytes > 0 ? min(1, log(Double(bytes) + 1) / log(Double(maxBytes) + 1)) : 0
        switch style {
        case .hub: return CGFloat(3.4 + rank * 5.0)
        case .relay: return CGFloat(1.6 + rank * 1.6)
        case .link: return CGFloat(2.2 + rank * 3.6)
        }
    }

    /// Node diameter from throughput, on a log scale and tightly bounded.
    static func nodeSize(bytes: UInt64, maxBytes: UInt64, base: CGFloat, spread: CGFloat) -> CGFloat {
        guard maxBytes > 0 else { return base }
        let rank = min(1, log(Double(bytes) + 1) / log(Double(maxBytes) + 1))
        return base + spread * CGFloat(rank)
    }
}

enum ByteFormat {
    static func compact(_ n: UInt64) -> String {
        let units = ["B", "KB", "MB", "GB", "TB"]
        var v = Double(n)
        var i = 0
        while v >= 1024, i < units.count - 1 {
            v /= 1024
            i += 1
        }
        return i == 0 ? "\(Int(v)) B" : String(format: "%.1f %@", v, units[i])
    }

    /// Short enough to sit under a node without wrapping.
    static func tight(_ n: UInt64) -> String {
        let units = ["B", "K", "M", "G", "T"]
        var v = Double(n)
        var i = 0
        while v >= 1024, i < units.count - 1 {
            v /= 1024
            i += 1
        }
        if i == 0 { return "\(Int(v))B" }
        return v >= 10 ? String(format: "%.0f%@", v, units[i]) : String(format: "%.1f%@", v, units[i])
    }
}
