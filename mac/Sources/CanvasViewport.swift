import AppKit
import SwiftUI

/// Pan and pinch for the graph canvas.
///
/// The zoom stepper is gone. A row of −/+/Fit/Hub buttons is the visual
/// signature of a debug tool: it puts a control panel in the corner of a
/// picture and asks the viewer to operate machinery. The canvas now opens at
/// one considered zoom and responds to the gestures the hardware already has -
/// pinch to scale, two fingers to pan - with no chrome at all.
struct CanvasViewport<Content: View>: View {
    @ViewBuilder var content: () -> Content
    let canvasSize: CGSize
    var focalPoint: CGPoint?
    /// The one zoom the canvas opens at, as a multiple of canvas-fit.
    var initialScale: CGFloat = 1.5

    @State private var scale: CGFloat = 1
    @State private var offset: CGSize = .zero
    @State private var didApplyInitial = false
    @GestureState private var dragDelta: CGSize = .zero
    @GestureState private var pinch: CGFloat = 1

    var body: some View {
        GeometryReader { geo in
            let fit = min(
                geo.size.width / max(canvasSize.width, 1),
                geo.size.height / max(canvasSize.height, 1)
            ) * 0.88
            let totalScale = scale * pinch * fit

            ZStack {
                content()
                    .frame(width: canvasSize.width, height: canvasSize.height)
                    .scaleEffect(totalScale)
                    .offset(
                        x: offset.width + dragDelta.width,
                        y: offset.height + dragDelta.height
                    )
            }
            .frame(width: geo.size.width, height: geo.size.height)
            .contentShape(Rectangle())
            .gesture(panGesture)
            .simultaneousGesture(pinchGesture)
            .clipped()
            // Two-finger scroll pans, which is what a trackpad scroll means
            // everywhere else on this platform. Zoom is pinch's job.
            .overlay(ScrollPanCapture { dx, dy in
                offset.width += dx
                offset.height += dy
            })
            .onAppear {
                guard !didApplyInitial else { return }
                didApplyInitial = true
                scale = initialScale
                if let focal = focalPoint {
                    offset = focalOffset(focal: focal, fit: fit)
                }
            }
            .onChange(of: canvasSize) { _, _ in
                guard let focal = focalPoint else { return }
                offset = focalOffset(focal: focal, fit: fit)
            }
        }
    }

    private func focalOffset(focal: CGPoint, fit: CGFloat) -> CGSize {
        let s = scale * fit
        return CGSize(
            width: -(focal.x - canvasSize.width / 2) * s,
            height: -(focal.y - canvasSize.height / 2) * s
        )
    }

    private var panGesture: some Gesture {
        DragGesture(minimumDistance: 4)
            .updating($dragDelta) { value, state, _ in state = value.translation }
            .onEnded { value in
                offset.width += value.translation.width
                offset.height += value.translation.height
            }
    }

    private var pinchGesture: some Gesture {
        MagnifyGesture()
            .updating($pinch) { value, state, _ in
                state = value.magnification
            }
            .onEnded { value in
                scale = min(3.2, max(0.5, scale * value.magnification))
            }
    }
}

/// Two-finger scroll as pan.
private struct ScrollPanCapture: NSViewRepresentable {
    var onPan: (CGFloat, CGFloat) -> Void

    func makeNSView(context: Context) -> ScrollPanView {
        let v = ScrollPanView()
        v.onPan = onPan
        return v
    }

    func updateNSView(_ nsView: ScrollPanView, context: Context) {
        nsView.onPan = onPan
    }
}

final class ScrollPanView: NSView {
    var onPan: ((CGFloat, CGFloat) -> Void)?

    override func scrollWheel(with event: NSEvent) {
        onPan?(event.scrollingDeltaX, event.scrollingDeltaY)
    }

    override var acceptsFirstResponder: Bool { true }
}
