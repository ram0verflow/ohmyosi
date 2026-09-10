import SwiftUI

enum TypeStyle {
    static func title(_ size: CGFloat = 15) -> Font {
        .system(size: size, weight: .semibold, design: .default)
    }

    static func body(_ size: CGFloat = 13) -> Font {
        .system(size: size, weight: .regular, design: .default)
    }

    static func caption(_ size: CGFloat = 11) -> Font {
        .system(size: size, weight: .regular, design: .default)
    }

    static func mono(_ size: CGFloat = 11) -> Font {
        .system(size: size, weight: .medium, design: .monospaced)
    }

    static func label(_ size: CGFloat = 10) -> Font {
        .system(size: size, weight: .medium, design: .default)
    }
}

struct GraphScene {
    let nodes: [GraphNode]
    let edges: [GraphEdge]
    let canvasSize: CGSize
}
