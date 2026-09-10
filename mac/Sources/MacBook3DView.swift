import AppKit
import SceneKit
import SwiftUI

/// Dimensionally accurate MacBook Pro 14" (M-series) — bundled USDZ from procedural GLB source.
struct MacBook3DView: View {
    var width: CGFloat = 320
    var zoom: CGFloat = 1

    private var height: CGFloat { width * 0.62 }

    var body: some View {
        Group {
            if BundleResources.macbookUSDZ != nil {
                MacBookSceneView()
            } else if BundleResources.macbookHero != nil {
                Image(nsImage: BundleResources.macbookHero!)
                    .resizable()
                    .interpolation(.high)
                    .aspectRatio(contentMode: .fit)
            } else {
                MacBookView(lidAngle: -118, scale: 0.85)
            }
        }
        .scaleEffect(zoom)
        .frame(width: width, height: height)
        .shadow(color: Theme.shadow, radius: 28, y: 16)
    }
}

private struct MacBookSceneView: NSViewRepresentable {
    func makeNSView(context: Context) -> SCNView {
        let view = SCNView()
        view.backgroundColor = .clear
        view.autoenablesDefaultLighting = false
        view.antialiasingMode = .multisampling4X
        view.allowsCameraControl = false

        guard let url = BundleResources.macbookUSDZ,
              let scene = try? SCNScene(url: url, options: nil) else { return view }

        let wrapper = SCNNode()
        for child in scene.rootNode.childNodes {
            wrapper.addChildNode(child.clone())
        }
        wrapper.eulerAngles = SCNVector3(-0.38, Float.pi, -0.12)
        wrapper.scale = SCNVector3(0.011, 0.011, 0.011)

        let stage = SCNScene()
        stage.rootNode.addChildNode(wrapper)

        let key = SCNNode()
        key.light = SCNLight()
        key.light?.type = .directional
        key.light?.intensity = 1400
        key.eulerAngles = SCNVector3(-0.9, 0.35, 0)
        stage.rootNode.addChildNode(key)

        let fill = SCNNode()
        fill.light = SCNLight()
        fill.light?.type = .omni
        fill.light?.intensity = 650
        fill.position = SCNVector3(-0.25, 0.12, 0.35)
        stage.rootNode.addChildNode(fill)

        let camera = SCNNode()
        camera.camera = SCNCamera()
        camera.camera?.fieldOfView = 34
        camera.position = SCNVector3(0, 0.08, 0.42)
        camera.look(at: SCNVector3(0, -0.02, 0))
        stage.rootNode.addChildNode(camera)

        view.scene = stage
        view.pointOfView = camera
        return view
    }

    func updateNSView(_ nsView: SCNView, context: Context) {}
}
