# ohmyosi — native macOS UI

SwiftUI app that connects to the Go daemon at `http://127.0.0.1:7777/events`.

## Requirements

- **Xcode** from the App Store (Command Line Tools alone are not enough for SwiftUI)
- Point the active developer directory at Xcode (one-time):

  ```sh
  sudo xcode-select -s /Applications/Xcode.app/Contents/Developer
  xcode-select -p   # should print .../Xcode.app/Contents/Developer
  ```

- Accept the Xcode license (one-time):

  ```sh
  sudo xcodebuild -license accept
  ```

- **ohmyosi daemon** running: `sudo ./ohmyosi` from the repo root

## Build & run

```sh
# Terminal 1 — capture daemon (needs root)
sudo ./ohmyosi

# Terminal 2 — native app
make mac-app
open dist/OhMyOSI.app
```

The graph opens in read-only mode. To change rules or system settings, copy the
current control token from the root-only file path printed by the daemon at
startup (`sudo cat '<path>'`), then paste it into Controls → Authorization.
The app keeps the token in memory and asks again after a daemon restart.

## DMG

```sh
make mac-dmg
open dist/OhMyOSI.dmg
```

## Design

- Native `NavigationSplitView` + unified toolbar (no custom gradient chrome)
- `.ultraThinMaterial` / `.regularMaterial` panels — Apple glass, not CSS gradients
- SF Pro system typography throughout
- Native toggle, list, and toolbar controls
- Center graph: Mac at the hub, processes and destinations on stable rings
- Inspector shows the Sherlock `trail` for each connection

The web prototype under `web/` is deprecated; use this app instead.
