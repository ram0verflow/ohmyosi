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
    @State private var isPanning = false

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
            // Include descendants so a drag that begins on an app, hostname,
            // cable label, or the MacBook still moves the whole scene.
            .simultaneousGesture(panGesture, including: .all)
            .simultaneousGesture(pinchGesture, including: .all)
            .clipped()
            // Observe scroll without placing an invisible NSView over the
            // graph. The old overlay intercepted node clicks and made the
            // canvas feel inert.
            .background(
                ScrollPanMonitor { dx, dy in
                    offset.width += dx
                    offset.height += dy
                }
            )
            .cursor(isPanning ? .closedHand : .openHand)
            .onTapGesture(count: 2) {
                withAnimation(.easeOut(duration: 0.22)) {
                    scale = initialScale
                    if let focal = focalPoint {
                        offset = focalOffset(focal: focal, fit: fit)
                    } else {
                        offset = .zero
                    }
                }
            }
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
            .updating($dragDelta) { value, state, _ in
                state = value.translation
                if !isPanning { isPanning = true }
            }
            .onEnded { value in
                offset.width += value.translation.width
                offset.height += value.translation.height
                isPanning = false
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

/// Two-finger scroll as pan, without becoming a hit-testing overlay.
private struct ScrollPanMonitor: NSViewRepresentable {
    var onPan: (CGFloat, CGFloat) -> Void

    func makeCoordinator() -> Coordinator { Coordinator(onPan: onPan) }

    func makeNSView(context: Context) -> NSView {
        let v = NSView(frame: .zero)
        context.coordinator.hostView = v
        context.coordinator.install()
        return v
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        context.coordinator.onPan = onPan
    }

    static func dismantleNSView(_ nsView: NSView, coordinator: Coordinator) {
        coordinator.uninstall()
    }

    final class Coordinator {
        weak var hostView: NSView?
        var onPan: (CGFloat, CGFloat) -> Void
        private var monitor: Any?

        init(onPan: @escaping (CGFloat, CGFloat) -> Void) {
            self.onPan = onPan
        }

        func install() {
            monitor = NSEvent.addLocalMonitorForEvents(matching: .scrollWheel) { [weak self] event in
                guard let self, let view = hostView, let window = view.window,
                      event.window === window else { return event }

                let point = view.convert(event.locationInWindow, from: nil)
                guard view.bounds.contains(point) else { return event }

                onPan(event.scrollingDeltaX, event.scrollingDeltaY)
                return nil
            }
        }

        func uninstall() {
            if let monitor { NSEvent.removeMonitor(monitor) }
            monitor = nil
        }
    }
}

private extension View {
    @ViewBuilder
    func cursor(_ cursor: NSCursor) -> some View {
        self.onHover { hovering in
            if hovering { cursor.push() } else { NSCursor.pop() }
        }
    }
}
