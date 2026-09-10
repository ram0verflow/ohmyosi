import AppKit
import Combine
import Foundation

/// Which side panel is showing. The graph always stays visible: the panels sit
/// beside it and the canvas insets to make room, never on top of it.
enum LeftPanel: Sendable {
    case none, attention, sites, rules, system
}

@MainActor
final class MonitorStore: ObservableObject {
    @Published private(set) var flows: [String: Flow] = [:]
    @Published private(set) var processes: [Int32: ProcessInfo] = [:]
    @Published private(set) var stats: Stats?
    @Published private(set) var host: HostInfo?
    @Published private(set) var isConnected = false
    @Published private(set) var lastError: String?
    @Published var selectedFlowID: String?
    @Published var showSelfTraffic = false
    @Published var showGraph = false
    @Published var popupNode: GraphNode?
    @Published var popupFlows: [Flow] = []
    /// The recent alert feed, newest first, bounded. Drives the triage list and
    /// the transient banner.
    @Published private(set) var recentAlerts: [Alert] = []
    /// Which side panel is open. Starts on attention so the score is visible
    /// from the first tick.
    @Published var leftPanel: LeftPanel = .attention
    /// Whether the triage list is expanded. It opens itself when something
    /// crosses into a band worth attention, and stays where the user puts it
    /// after that - a panel that reopens on every alert is a panel you close
    /// forever.
    @Published var showTriage = false
    /// Block/allow rules, mirrored from the daemon's /api/rules.
    @Published private(set) var rules: [BlockRule] = []
    /// Enforcement state and capabilities, from /api/status.
    @Published private(set) var enforcing = false
    @Published private(set) var isRoot = false
    @Published private(set) var interfaces: [String] = []
    /// Transient feedback for an action (import count, new MAC, an error).
    @Published var actionMessage: String?
    /// Every destination seen this session, keyed by name/ip. Never pruned when a
    /// flow expires, which is exactly what makes it the "all sites" answer.
    @Published private(set) var destinations: [String: DestinationSeen] = [:]

    private var client: EventStreamClient?
    private let daemonURL: URL

    init(daemonURL: URL = URL(string: "http://127.0.0.1:7777/events")!) {
        self.daemonURL = daemonURL
    }

    func connect() {
        client?.stop()
        let client = EventStreamClient(url: daemonURL)
        self.client = client
        client.onStateChange = { [weak self] connected in
            Task { @MainActor in self?.isConnected = connected }
        }
        client.onError = { [weak self] message in
            Task { @MainActor in self?.lastError = message }
        }
        client.onEnvelope = { [weak self] envelope in
            Task { @MainActor in self?.apply(envelope) }
        }
        client.start()
        loadRules()
        loadStatus()
    }

    func disconnect() {
        client?.stop()
        client = nil
        isConnected = false
    }

    var visibleFlows: [Flow] {
        flows.values
            .filter { showSelfTraffic || !($0.isSelf ?? false) }
            .sorted { $0.totalBytes > $1.totalBytes }
    }

    /// Flows the scorer thinks are worth a look, loudest first. This is the
    /// whole point of surfacing the score: the one question someone opens this
    /// asking - "what is my machine doing that I did not expect?" - answered
    /// without hunting the canvas for it.
    var attentionFlows: [Flow] {
        visibleFlows
            .filter { $0.band.wantsAttention }
            .sorted { $0.suspicionScore > $1.suspicionScore }
    }

    /// The worst band currently on screen, for the header pip.
    var peakBand: SuspicionBand {
        attentionFlows.first?.band ?? .quiet
    }

    var selectedFlow: Flow? {
        guard let id = selectedFlowID else { return nil }
        return flows[id]
    }

    func finishSplash() {
        showGraph = true
    }

    func openPopup(for node: GraphNode, layoutFlows: [Flow]) {
        popupNode = node
        // The machine node stands for the whole session: show every visible flow,
        // busiest first, so clicking the Mac is "what am I talking to overall".
        if node.kind == .machine {
            popupFlows = layoutFlows.sorted { $0.totalBytes > $1.totalBytes }
        } else {
            popupFlows = GraphLayout.flows(matching: node, in: layoutFlows, processes: processes)
                .sorted { $0.totalBytes > $1.totalBytes }
        }
    }

    // MARK: - Destinations seen this session

    private func upsertDestination(_ flow: Flow) {
        let key = flow.remote.domain ?? flow.remote.host ?? flow.remote.ip
        guard !key.isEmpty else { return }
        let app = processes[flow.pid]?.displayName ?? flow.comm
        var d = destinations[key] ?? DestinationSeen(
            id: key, name: flow.remote.displayName, org: flow.remote.org,
            lastApp: app, bytes: 0, lastSeen: flow.last_seen, firstSeen: flow.first_seen,
            band: .quiet, blocked: false
        )
        d.name = flow.remote.displayName
        if let org = flow.remote.org { d.org = org }
        d.lastApp = app
        d.bytes = max(d.bytes, flow.totalBytes)
        d.lastSeen = max(d.lastSeen, flow.last_seen)
        d.firstSeen = min(d.firstSeen, flow.first_seen)
        if flow.band > d.band { d.band = flow.band }
        d.blocked = d.blocked || (flow.blocked ?? false)
        destinations[key] = d
    }

    /// Every destination seen this session, most recent first, optionally
    /// filtered by a search string.
    func sites(matching query: String) -> [DestinationSeen] {
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        return destinations.values
            .filter { q.isEmpty || $0.name.lowercased().contains(q) || ($0.org?.lowercased().contains(q) ?? false) || $0.lastApp.lowercased().contains(q) }
            .sorted { $0.lastSeen > $1.lastSeen }
    }

    // MARK: - Rules API

    private func apiURL(path: String, query: String? = nil) -> URL? {
        guard var c = URLComponents(url: daemonURL, resolvingAgainstBaseURL: false) else { return nil }
        c.path = path
        c.query = query
        return c.url
    }

    func loadRules() {
        guard let url = apiURL(path: "/api/rules") else { return }
        URLSession.shared.dataTask(with: url) { [weak self] data, _, _ in
            guard let data, let list = try? JSONDecoder().decode([BlockRule].self, from: data) else { return }
            Task { @MainActor in self?.rules = list }
        }.resume()
    }

    func addRule(scope: String, match: String, action: String = "block", note: String? = nil) {
        guard let url = apiURL(path: "/api/rules"), !match.isEmpty else { return }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try? JSONSerialization.data(withJSONObject: [
            "scope": scope, "match": match, "action": action, "note": note ?? "",
        ])
        URLSession.shared.dataTask(with: req) { [weak self] _, _, _ in
            Task { @MainActor in self?.loadRules() }
        }.resume()
    }

    func deleteRule(id: String) {
        guard let url = apiURL(path: "/api/rules", query: "id=\(id)") else { return }
        var req = URLRequest(url: url)
        req.httpMethod = "DELETE"
        URLSession.shared.dataTask(with: req) { [weak self] _, _, _ in
            Task { @MainActor in self?.loadRules() }
        }.resume()
    }

    /// Remove an entire imported category in one call, rather than thousands of
    /// single deletes.
    func deleteRuleGroup(note: String) {
        let q = "note=" + (note.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? note)
        guard let url = apiURL(path: "/api/rules", query: q) else { return }
        var req = URLRequest(url: url)
        req.httpMethod = "DELETE"
        URLSession.shared.dataTask(with: req) { [weak self] _, _, _ in
            Task { @MainActor in self?.loadRules() }
        }.resume()
    }

    /// Rules split into imported category groups (note "blocklist: X") and the
    /// individual, hand-made rules. Lets the panel show one row per category
    /// with its list kept separate, instead of thousands of rows.
    var ruleGroups: [(note: String, title: String, rules: [BlockRule])] {
        var groups: [String: [BlockRule]] = [:]
        for r in rules where r.note?.hasPrefix("blocklist:") == true {
            groups[r.note!, default: []].append(r)
        }
        return groups.keys.sorted().map { note in
            let label = note.replacingOccurrences(of: "blocklist:", with: "").trimmingCharacters(in: .whitespaces)
            return (note, label.isEmpty ? "Blocklist" : label.capitalized, groups[note]!)
        }
    }

    var manualRules: [BlockRule] {
        rules.filter { $0.note?.hasPrefix("blocklist:") != true }
    }

    /// True when a destination already has a block rule, so the UI shows
    /// "unblock" rather than offering to block it twice.
    func isBlocked(domain: String?, host: String?, ip: String) -> Bool {
        rules.contains { r in
            guard r.enabled, r.isBlock else { return false }
            let m = r.match.lowercased()
            switch r.scope {
            case "domain": return m == (domain?.lowercased() ?? "") || m == (host?.lowercased() ?? "")
            case "dest": return m == ip.lowercased()
            default: return false
            }
        }
    }

    // MARK: - System actions (enforcement, blocklists, spoofing)

    func loadStatus() {
        guard let url = apiURL(path: "/api/status") else { return }
        URLSession.shared.dataTask(with: url) { [weak self] data, _, _ in
            guard let data,
                  let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
            else { return }
            Task { @MainActor in
                self?.enforcing = obj["enforcing"] as? Bool ?? false
                self?.isRoot = obj["root"] as? Bool ?? false
                self?.interfaces = obj["interfaces"] as? [String] ?? []
            }
        }.resume()
    }

    /// POST a JSON body to an action endpoint and hand the decoded reply back on
    /// the main actor. Shared by every system action so they behave alike.
    private func post(_ path: String, body: [String: Any], then: @escaping ([String: Any]?) -> Void) {
        guard let url = apiURL(path: path) else { return }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try? JSONSerialization.data(withJSONObject: body)
        URLSession.shared.dataTask(with: req) { data, resp, err in
            let obj = data.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] } ?? nil
            Task { @MainActor in
                if let e = obj?["error"] as? String { self.actionMessage = e }
                else if err != nil { self.actionMessage = "Action failed — is the daemon running as root?" }
                then(obj)
            }
        }.resume()
    }

    func setEnforce(_ on: Bool) {
        post("/api/enforce", body: ["on": on]) { [weak self] obj in
            if let e = obj?["enforcing"] as? Bool {
                self?.enforcing = e
                self?.actionMessage = e ? "Enforcement on — matching flows are being blocked" : "Enforcement off"
            }
            self?.loadStatus()
        }
    }

    /// Import a category ("adult", "ads", "gambling", "social"), URL or path.
    func importBlocklist(_ src: String) {
        actionMessage = "Importing \(src) blocklist…"
        post("/api/blocklist", body: ["src": src]) { [weak self] obj in
            if let n = obj?["imported"] as? Int {
                self?.actionMessage = "Imported \(n) domains from \(src). Turn on enforcement to apply."
            }
            self?.loadRules()
        }
    }

    func spoofMAC(_ iface: String) {
        post("/api/spoof-mac", body: ["iface": iface]) { [weak self] obj in
            if let mac = obj?["mac"] as? String {
                self?.actionMessage = "\(iface) MAC is now \(mac) — rejoin Wi-Fi for it to take effect"
            }
        }
    }

    func setHostname(_ name: String) {
        post("/api/hostname", body: ["name": name]) { [weak self] obj in
            if obj?["ok"] as? Bool == true {
                self?.actionMessage = "Hostname set to \(name)"
            }
        }
    }

    // MARK: - Export

    /// Write the session's flows to a JSON file in Downloads and reveal it. A
    /// record you can keep, diff and hand to someone else - the difference
    /// between a live view and a forensic tool.
    @discardableResult
    func exportSession() -> URL? {
        struct Snapshot: Encodable {
            let exportedAt: Double
            let host: HostInfo?
            let stats: Stats?
            let flows: [Flow]
            let processes: [ProcessInfo]
        }
        let snap = Snapshot(
            exportedAt: Date().timeIntervalSince1970, host: host, stats: stats,
            flows: visibleFlows, processes: Array(processes.values)
        )
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? enc.encode(snap),
              let dir = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first
        else { return nil }
        let stamp = ISO8601DateFormatter().string(from: Date()).replacingOccurrences(of: ":", with: "-")
        let url = dir.appendingPathComponent("ohmyosi-session-\(stamp).json")
        do {
            try data.write(to: url)
            NSWorkspace.shared.activateFileViewerSelecting([url])
            return url
        } catch {
            lastError = "Could not export: \(error.localizedDescription)"
            return nil
        }
    }

    private func apply(_ envelope: Envelope) {
        if let h = envelope.host { host = h }
        if let s = envelope.stats { stats = s }
        for proc in envelope.procs ?? [] {
            processes[proc.pid] = proc
        }
        for flow in envelope.flows ?? [] {
            flows[flow.id] = flow
            if !(flow.isSelf ?? false) { upsertDestination(flow) }
        }
        for id in envelope.gone ?? [] {
            flows.removeValue(forKey: id)
            if selectedFlowID == id { selectedFlowID = nil }
        }
        if let alerts = envelope.alerts, !alerts.isEmpty {
            recentAlerts.insert(contentsOf: alerts.reversed(), at: 0)
            if recentAlerts.count > 40 {
                recentAlerts = Array(recentAlerts.prefix(40))
            }
        }
        lastError = nil
    }
}

final class EventStreamClient: NSObject {
    var onEnvelope: ((Envelope) -> Void)?
    var onStateChange: ((Bool) -> Void)?
    var onError: ((String) -> Void)?

    private let url: URL
    private var task: URLSessionDataTask?
    private lazy var session: URLSession = {
        URLSession(configuration: .default, delegate: self, delegateQueue: nil)
    }()
    private var buffer = Data()

    init(url: URL) {
        self.url = url
    }

    func start() {
        stop()
        var request = URLRequest(url: url)
        request.setValue("text/event-stream", forHTTPHeaderField: "Accept")
        request.timeoutInterval = .infinity
        task = session.dataTask(with: request)
        task?.resume()
    }

    func stop() {
        task?.cancel()
        task = nil
        buffer.removeAll()
        onStateChange?(false)
    }

    private func parseBuffer() {
        guard let text = String(data: buffer, encoding: .utf8) else { return }
        let parts = text.components(separatedBy: "\n\n")
        let complete = parts.dropLast()
        let remainder = parts.last ?? ""
        buffer = Data(remainder.utf8)

        for block in complete {
            for line in block.split(separator: "\n") {
                guard line.hasPrefix("data:") else { continue }
                let json = line.dropFirst(5).trimmingCharacters(in: .whitespaces)
                guard let data = json.data(using: .utf8) else { continue }
                do {
                    let envelope = try JSONDecoder().decode(Envelope.self, from: data)
                    onEnvelope?(envelope)
                } catch {
                    onError?("Could not read update from daemon")
                }
            }
        }
    }
}

extension EventStreamClient: URLSessionDataDelegate {
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse, completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        if let http = response as? HTTPURLResponse, http.statusCode == 200 {
            onStateChange?(true)
            completionHandler(.allow)
        } else {
            onError?("Daemon not reachable — run sudo ohmyosi first")
            onStateChange?(false)
            completionHandler(.cancel)
        }
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        buffer.append(data)
        parseBuffer()
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        onStateChange?(false)
        if let error, (error as NSError).code != NSURLErrorCancelled {
            onError?("Lost connection to ohmyosi")
        }
    }
}
