import AppKit
import SwiftUI

enum VerifyMode {
    static var isActive: Bool { CommandLine.arguments.contains("--verify") }

    static var snapshotPath: String? {
        let args = CommandLine.arguments
        guard let i = args.firstIndex(of: "--snapshot"), i + 1 < args.count else { return nil }
        return args[i + 1]
    }
}

@MainActor
enum SnapshotExporter {
    static func capture<V: View>(_ view: V, size: CGSize, to path: String) -> Bool {
        let renderer = ImageRenderer(content: view.frame(width: size.width, height: size.height))
        renderer.scale = 2
        guard let cgImage = renderer.cgImage else { return false }
        let rep = NSBitmapImageRep(cgImage: cgImage)
        guard let png = rep.representation(using: .png, properties: [:]) else { return false }
        try? png.write(to: URL(fileURLWithPath: path))
        return FileManager.default.fileExists(atPath: path)
    }
}
