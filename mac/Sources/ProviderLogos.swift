import Foundation

/// Maps ASN/org/IP hints to a domain whose favicon identifies the operator.
enum ProviderLogos {
    private static let rules: [(keys: [String], domain: String)] = [
        (["amazon", "aws", "amazon data services"], "aws.amazon.com"),
        (["cloudflare"], "cloudflare.com"),
        (["google", "1e100.net", "google cloud"], "google.com"),
        (["microsoft", "azure"], "microsoft.com"),
        (["apple", "aaplimg"], "apple.com"),
        (["meta", "facebook"], "meta.com"),
        (["akamai"], "akamai.com"),
        (["fastly"], "fastly.com"),
        (["digitalocean"], "digitalocean.com"),
        (["oracle", "oci "], "oracle.com"),
        (["verizon", "uunet"], "verizon.com"),
        (["level3", "lumen", "centurylink"], "lumen.com"),
        (["hetzner"], "hetzner.com"),
        (["ovh"], "ovhcloud.com"),
        (["linode", "akamai connected cloud"], "linode.com"),
        (["github"], "github.com"),
        (["openai"], "openai.com"),
        (["anthropic"], "anthropic.com"),
        (["cursor"], "cursor.com"),
        (["netflix"], "netflix.com"),
        (["cloudfront"], "aws.amazon.com"),
    ]

    static func domain(for org: String?, asnOrg: String? = nil) -> String? {
        let hay = [org, asnOrg].compactMap { $0?.lowercased() }.joined(separator: " ")
        guard !hay.isEmpty else { return nil }
        for rule in rules {
            if rule.keys.contains(where: { hay.contains($0) }) { return rule.domain }
        }
        return nil
    }

    static func faviconURL(for org: String?, asnOrg: String? = nil) -> URL? {
        guard let domain = domain(for: org, asnOrg: asnOrg) else { return nil }
        return faviconURL(forDomain: domain)
    }

    static func faviconURL(forDomain domain: String) -> URL? {
        let clean = domain.trimmingCharacters(in: .whitespaces).lowercased()
        guard !clean.isEmpty else { return nil }
        var c = URLComponents(string: "https://www.google.com/s2/favicons")
        c?.queryItems = [
            URLQueryItem(name: "domain", value: clean),
            URLQueryItem(name: "sz", value: "128"),
        ]
        return c?.url
    }

    static func faviconURL(for endpoint: Endpoint, daemonBase: URL) -> URL? {
        if let f = endpoint.favicon {
            return daemonBase.appendingPathComponent("favicons/\(f)")
        }
        if let d = endpoint.domain, !d.isEmpty {
            return faviconURL(forDomain: d)
        }
        if let h = endpoint.host, !h.isEmpty, !ForensicMap.isInfrastructureHost(h) {
            return faviconURL(forDomain: ForensicMap.registrablePublic(h))
        }
        return faviconURL(for: endpoint.org, asnOrg: endpoint.asn_org)
    }
}
