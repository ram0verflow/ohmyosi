import Foundation

/// Forensic resolution: DNS/CDN are intermediates; finals are intent (SNI/DNS/query).
enum ForensicMap {
    struct Link: Hashable {
        let processKey: String
        let processLabel: String
        let pid: Int32
        let iconURL: URL?
        let localPath: String?
        let intermediateKey: String?
        let intermediateLabel: String?
        let intermediateIconURL: URL?
        let destinationKey: String
        let destinationLabel: String
        let destinationSubtitle: String?
        let destinationIconURL: URL?
        let bytes: UInt64
        let processHue: Double
        let destinationHue: Double

        func addingBytes(_ extra: UInt64) -> Link {
            Link(
                processKey: processKey, processLabel: processLabel, pid: pid,
                iconURL: iconURL, localPath: localPath,
                intermediateKey: intermediateKey, intermediateLabel: intermediateLabel,
                intermediateIconURL: intermediateIconURL,
                destinationKey: destinationKey, destinationLabel: destinationLabel,
                destinationSubtitle: destinationSubtitle, destinationIconURL: destinationIconURL,
                bytes: bytes + extra,
                processHue: processHue, destinationHue: destinationHue
            )
        }
    }

    private static let resolverIPs: Set<String> = [
        "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
        "208.67.222.222", "208.67.220.220",
    ]

    private static let infrastructureHosts: [String] = [
        "one.one.one.one", "cloudflare-dns.com", "dns.google", "dns.cloudflare.com",
        "amazonaws.com", "1e100.net", "aaplimg.com", "akamaiedge.net", "cloudfront.net",
        "compute.internal", "bc.googleusercontent.com",
    ]

    private static let infrastructureOrgs: [String] = [
        "cloudflare", "google llc", "amazon", "akamai", "fastly",
    ]

    static func expand(
        _ flows: [Flow],
        processes: [Int32: ProcessInfo],
        daemonBase: URL
    ) -> [Link] {
        flows.flatMap { links(for: $0, processes: processes, daemonBase: daemonBase) }
    }

    private static func links(
        for flow: Flow,
        processes: [Int32: ProcessInfo],
        daemonBase: URL
    ) -> [Link] {
        let procLabel = GraphReducer.processName(for: flow, processes: processes)
        let pinfo = processes[flow.pid]
        let iconURL = pinfo?.icon_id.map { daemonBase.appendingPathComponent("icons/\($0).png") }
        let path = pinfo?.path
        let bytes = flow.totalBytes
        let procHue = GraphReducer.stableHue(procLabel)

        if isResolver(flow.remote), let queries = flow.queries, !queries.isEmpty {
            let iKey = "i:\(flow.remote.ip)"
            let iLabel = intermediateLabel(for: flow.remote)
            let iIcon = ProviderLogos.faviconURL(for: flow.remote, daemonBase: daemonBase)
                ?? ProviderLogos.faviconURL(for: "Cloudflare", asnOrg: flow.remote.asn_org)
            return queries.map { q in
                let host = normalizeHost(q)
                let destKey = "d:\(host)"
                let destIcon = ProviderLogos.faviconURL(forDomain: registrablePublic(host))
                return Link(
                    processKey: procLabel, processLabel: procLabel, pid: flow.pid,
                    iconURL: iconURL, localPath: path,
                    intermediateKey: iKey, intermediateLabel: iLabel, intermediateIconURL: iIcon,
                    destinationKey: destKey, destinationLabel: host,
                    destinationSubtitle: "DNS lookup",
                    destinationIconURL: destIcon,
                    bytes: max(bytes / UInt64(queries.count), 1),
                    processHue: procHue, destinationHue: GraphReducer.stableHue(host)
                )
            }
        }

        guard let final = finalDestination(for: flow, browser: GraphReducer.isBrowser(procLabel)) else { return [] }

        var iKey: String?
        var iLabel: String?
        var iIcon: URL?
        if isResolver(flow.remote) || (flow.remote.host.map { isInfrastructureHost($0) } ?? false) {
            iKey = "i:\(flow.remote.ip)"
            iLabel = intermediateLabel(for: flow.remote)
            iIcon = ProviderLogos.faviconURL(for: flow.remote, daemonBase: daemonBase)
        } else if let org = flow.remote.org, isInfrastructureOrg(org), final.label.lowercased() != org.lowercased() {
            iKey = "i:\(org.lowercased())"
            iLabel = org
            iIcon = ProviderLogos.faviconURL(for: org, asnOrg: flow.remote.asn_org)
        }

        let destIcon = ProviderLogos.faviconURL(for: flow.remote, daemonBase: daemonBase)
            ?? ProviderLogos.faviconURL(forDomain: final.key)
        let subtitle = hostingSubtitle(for: flow.remote, final: final.label)

        return [Link(
            processKey: procLabel, processLabel: procLabel, pid: flow.pid,
            iconURL: iconURL, localPath: path,
            intermediateKey: iKey, intermediateLabel: iLabel, intermediateIconURL: iIcon,
            destinationKey: "d:\(final.key)", destinationLabel: final.label,
            destinationSubtitle: subtitle,
            destinationIconURL: destIcon,
            bytes: bytes,
            processHue: procHue, destinationHue: GraphReducer.stableHue(final.key)
        )]
    }

    struct FinalDest {
        let key: String
        let label: String
    }

    static func finalDestination(for flow: Flow, browser: Bool = false) -> FinalDest? {
        let r = flow.remote

        if let h = r.host, isIntentHost(h, src: r.host_src) {
            let label = browser ? h : displayHost(h)
            let key = browser ? h.lowercased() : registrablePublic(h)
            return FinalDest(key: key, label: label)
        }
        if let d = r.domain, !d.isEmpty, !isInfrastructureHost(d) {
            return FinalDest(key: browser ? d : registrablePublic(d), label: d)
        }
        if let queries = flow.queries {
            for q in queries.reversed() where !isInfrastructureHost(q) {
                let host = normalizeHost(q)
                return FinalDest(key: browser ? host : registrablePublic(host), label: host)
            }
        }
        if let org = r.org, GraphReducer.isReadableOrg(org), !isInfrastructureOrg(org) {
            return FinalDest(key: org, label: org)
        }
        if let asn = r.asn_org, GraphReducer.isReadableOrg(asn), !isInfrastructureOrg(asn) {
            return FinalDest(key: "AS\(r.asn ?? 0)", label: asn)
        }
        let ip = r.ip
        if !ip.isEmpty {
            let label = shortIP(ip)
            let key = ip
            return FinalDest(key: key, label: label)
        }
        return nil
    }

    static func registrablePublic(_ h: String) -> String {
        let clean = h.trimmingCharacters(in: .whitespaces).lowercased()
        let parts = clean.split(separator: ".")
        guard parts.count >= 2 else { return clean }
        return parts.suffix(2).joined(separator: ".")
    }

    private static func normalizeHost(_ q: String) -> String {
        q.trimmingCharacters(in: .whitespaces).lowercased()
    }

    private static func isResolver(_ e: Endpoint) -> Bool {
        if e.port == 53 { return true }
        if resolverIPs.contains(e.ip) { return true }
        if let h = e.host?.lowercased() {
            if h.contains("dns") { return true }
            if h == "one.one.one.one" { return true }
        }
        return false
    }

    private static func intermediateLabel(for e: Endpoint) -> String {
        if let org = e.org, !org.isEmpty { return org }
        if let h = e.host, !h.isEmpty { return displayHost(h) }
        return shortIP(e.ip)
    }

    static func isIntentHost(_ h: String, src: String?) -> Bool {
        if GraphReducer.looksLikeDate(h) { return false }
        if isInfrastructureHost(h) { return false }
        guard let src else { return !h.isEmpty }
        return src == "sni" || src == "dns" || src == "http"
    }

    static func isInfrastructureHost(_ h: String) -> Bool {
        let lower = h.lowercased()
        return infrastructureHosts.contains(where: { lower.contains($0) })
    }

    static func isInfrastructureOrg(_ o: String) -> Bool {
        let lower = o.lowercased()
        return infrastructureOrgs.contains(where: { lower.contains($0) })
    }

    private static func displayHost(_ h: String) -> String {
        let parts = h.split(separator: ".")
        guard parts.count >= 2 else { return h }
        if parts.count <= 3 { return h }
        return parts.suffix(3).joined(separator: ".")
    }

    private static func hostingSubtitle(for r: Endpoint, final: String) -> String? {
        if let org = r.org, !org.isEmpty, org.lowercased() != final.lowercased() {
            return isInfrastructureOrg(org) ? "hosted on \(org)" : org
        }
        if final.contains(".") == false || final.contains("…") {
            if let org = r.org, !org.isEmpty { return org }
            if let asn = r.asn_org, !asn.isEmpty { return asn }
        }
        return nil
    }

    private static func shortIP(_ ip: String) -> String {
        ip.count > 22 ? String(ip.prefix(12)) + "…" : ip
    }
}
