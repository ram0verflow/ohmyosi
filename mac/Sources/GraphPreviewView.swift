import SwiftUI

struct GraphSnapshotView: View {
    let scene: GraphScene

    var body: some View {
        GraphCanvasView(scene: scene, stats: nil, onTapNode: { _ in })
            .environmentObject(IconCache())
    }
}
