import CoreGraphics

/// Push overlapping nodes apart on the virtual canvas.
enum GraphCollision {
    static func resolve(
        _ nodes: [GraphNode],
        center: CGPoint,
        machineSize: CGFloat,
        padding: CGFloat = 22,
        passes: Int = 120
    ) -> [GraphNode] {
        guard nodes.count > 1 else { return nodes }
        var out = nodes
        let machineRadius = machineSize * 0.5 + padding + 12

        for _ in 0..<passes {
            var moved = false
            for i in 0..<out.count {
                for j in (i + 1)..<out.count {
                    if out[i].kind == .machine || out[j].kind == .machine { continue }
                    let a = out[i], b = out[j]
                    let minDist = (a.size + b.size) * 0.5 + padding
                    let dx = b.x - a.x
                    let dy = b.y - a.y
                    let d = max(sqrt(dx * dx + dy * dy), 0.001)
                    if d < minDist {
                        let push = (minDist - d) * 0.72
                        let nx = dx / d, ny = dy / d
                        out[i] = a.moved(by: -nx * push, -ny * push)
                        out[j] = b.moved(by: nx * push, ny * push)
                        moved = true
                    }
                }
            }

            for i in 0..<out.count {
                guard out[i].kind != .machine else { continue }
                let n = out[i]
                let nodeRadius = n.size * 0.5 + padding * 0.5
                let dx = n.x - center.x
                let dy = n.y - center.y
                let d = max(sqrt(dx * dx + dy * dy), 0.001)
                let minDist = machineRadius + nodeRadius
                if d < minDist {
                    let push = (minDist - d) * 0.85
                    out[i] = n.moved(by: dx / d * push, dy / d * push)
                    moved = true
                }
            }

            if !moved { break }
        }
        return out
    }
}

private extension GraphNode {
    func moved(by dx: CGFloat, _ dy: CGFloat) -> GraphNode {
        GraphNode(
            id: id, kind: kind, title: title, subtitle: subtitle,
            x: x + dx, y: y + dy, size: size,
            iconURL: iconURL, localIconPath: localIconPath,
            accentHue: accentHue, bytes: bytes
        )
    }
}
