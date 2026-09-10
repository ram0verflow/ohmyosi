import CoreGraphics
import SwiftUI

/// Routes branches in separate lanes so paths do not overlap.
enum GraphPathRouter {
    static func cubicPoints(from: CGPoint, to: CGPoint, lane: Int, total: Int) -> [CGPoint] {
        let spread = max(total - 1, 1)
        let laneF = CGFloat(lane) - CGFloat(spread) / 2
        let lift = 50 + abs(laneF) * 14
        let spreadX = laneF * 22

        let c1 = CGPoint(x: from.x + spreadX * 0.3, y: from.y - lift)
        let c2 = CGPoint(x: to.x - spreadX * 0.3, y: to.y - lift * 0.65)
        return [from, c1, c2, to]
    }

    static func bezierPoint(_ pts: [CGPoint], t: CGFloat) -> CGPoint {
        guard pts.count == 4 else { return pts.first ?? .zero }
        let u = 1 - t
        let a = pts[0], b = pts[1], c = pts[2], d = pts[3]
        let x = u*u*u*a.x + 3*u*u*t*b.x + 3*u*t*t*c.x + t*t*t*d.x
        let y = u*u*u*a.y + 3*u*u*t*b.y + 3*u*t*t*c.y + t*t*t*d.y
        return CGPoint(x: x, y: y)
    }

    static func curvePath(_ pts: [CGPoint]) -> Path {
        var p = Path()
        guard pts.count == 4 else { return p }
        p.move(to: pts[0])
        p.addCurve(to: pts[3], control1: pts[1], control2: pts[2])
        return p
    }

    static func trimmedCurve(_ pts: [CGPoint], progress: CGFloat) -> Path {
        guard pts.count == 4, progress > 0 else { return Path() }
        var p = Path()
        p.move(to: pts[0])
        let steps = max(Int(progress * 48), 2)
        for i in 1...steps {
            let t = CGFloat(i) / 48 * min(progress, 1)
            p.addLine(to: bezierPoint(pts, t: min(t, 1)))
        }
        return p
    }

    /// Branches exit the top edge of the laptop screen (front view).
    static func laptopAnchor(screenCenter: CGPoint, screenWidth: CGFloat, slot: Int, total: Int) -> CGPoint {
        let spread = max(total - 1, 1)
        let t = total <= 1 ? 0.5 : CGFloat(slot) / CGFloat(spread)
        let x = screenCenter.x - screenWidth * 0.42 + t * screenWidth * 0.84
        return CGPoint(x: x, y: screenCenter.y - 42)
    }
}
