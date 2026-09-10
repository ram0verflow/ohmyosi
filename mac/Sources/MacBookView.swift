import SwiftUI

/// Vector MacBook fallback when USDZ is unavailable.
struct MacBookView: View {
    var lidAngle: Double = -118
    var scale: CGFloat = 1

    private var s: CGFloat { scale }

    var body: some View {
        ZStack {
            baseDeck
            lidGroup
        }
        .rotation3DEffect(.degrees(48), axis: (x: 1, y: 0, z: 0), perspective: 0.42)
        .rotation3DEffect(.degrees(16), axis: (x: 0, y: 1, z: 0), perspective: 0.42)
        .shadow(color: Theme.shadow, radius: 40 * s, y: 28 * s)
    }

    private var baseDeck: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 14 * s, style: .continuous)
                .fill(Theme.starlight)
                .frame(width: 300 * s, height: 195 * s)
                .overlay(
                    RoundedRectangle(cornerRadius: 14 * s, style: .continuous)
                        .strokeBorder(Theme.starlightDeep, lineWidth: 1)
                )

            VStack(spacing: 8 * s) {
                keyboardPlane
                trackpadPlane
            }
            .padding(.top, 18 * s)
            .padding(.bottom, 14 * s)
        }
    }

    private var lidGroup: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 12 * s, style: .continuous)
                .fill(Theme.starlight)
                .frame(width: 300 * s, height: 188 * s)
                .overlay(
                    RoundedRectangle(cornerRadius: 12 * s, style: .continuous)
                        .strokeBorder(Theme.starlightDeep, lineWidth: 1)
                )

            RoundedRectangle(cornerRadius: 8 * s, style: .continuous)
                .fill(Theme.screenGlass)
                .frame(width: 272 * s, height: 168 * s)
                .overlay(alignment: .top) {
                    Capsule()
                        .fill(Color.black)
                        .frame(width: 32 * s, height: 8 * s)
                        .padding(.top, 7 * s)
                }
                .overlay {
                    RoundedRectangle(cornerRadius: 8 * s, style: .continuous)
                        .strokeBorder(Color(white: 0.2), lineWidth: 0.75)
                }
        }
        .rotation3DEffect(
            .degrees(lidAngle),
            axis: (x: 1, y: 0, z: 0),
            anchor: .bottom,
            perspective: 0.55
        )
        .offset(y: -96 * s)
    }

    private var keyboardPlane: some View {
        VStack(spacing: 4 * s) {
            ForEach(0..<4, id: \.self) { _ in
                HStack(spacing: 4 * s) {
                    ForEach(0..<12, id: \.self) { _ in
                        RoundedRectangle(cornerRadius: 2 * s, style: .continuous)
                            .fill(Theme.keyboard.opacity(0.92))
                            .frame(width: 10 * s, height: 6 * s)
                    }
                }
            }
        }
        .padding(.horizontal, 16 * s)
    }

    private var trackpadPlane: some View {
        RoundedRectangle(cornerRadius: 5 * s, style: .continuous)
            .fill(Theme.starlightDeep.opacity(0.85))
            .frame(width: 96 * s, height: 58 * s)
    }
}

struct SplashView: View {
    var connected: Bool
    var onFinished: () -> Void

    @State private var heroZoom: CGFloat = 0.55
    @State private var revealed = false
    @State private var fadeOut = false

    var body: some View {
        ZStack {
            Theme.canvas.ignoresSafeArea()

            VStack(spacing: 36) {
                MacBook3DView(width: 440, zoom: heroZoom)

                VStack(spacing: 8) {
                    Text("ohmyosi")
                        .font(.system(size: 32, weight: .light, design: .default))
                        .tracking(1.2)
                        .foregroundStyle(Theme.ink)
                    Text(connected ? "Forensic network mapping" : "Waiting for capture daemon")
                        .font(.system(size: 14, weight: .regular))
                        .foregroundStyle(Theme.inkSecondary)
                }
                .opacity(revealed ? 1 : 0)
            }
        }
        .opacity(fadeOut ? 0 : 1)
        .onAppear {
            withAnimation(.spring(response: 1.35, dampingFraction: 0.82)) { heroZoom = 1.22 }
            withAnimation(.easeOut(duration: 0.8).delay(0.45)) { revealed = true }
            scheduleExit()
        }
        .onChange(of: connected) { _, now in
            if now { scheduleExit() }
        }
    }

    private func scheduleExit() {
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.8) {
            guard connected else { return }
            withAnimation(.easeOut(duration: 0.5)) { fadeOut = true }
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { onFinished() }
        }
    }
}
