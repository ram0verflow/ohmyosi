import SwiftUI

@main
struct OhMyOSIApp: App {
    @StateObject private var store = MonitorStore()
    @StateObject private var icons = IconCache()

    var body: some Scene {
        WindowGroup {
            MainView()
                .environmentObject(store)
                .environmentObject(icons)
        }
        .windowStyle(.hiddenTitleBar)
        .defaultSize(width: 1400, height: 960)
        .commands {
            CommandGroup(replacing: .newItem) {}
        }
    }
}
