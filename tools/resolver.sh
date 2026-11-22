# Sourced by the capture scripts (POSIX sh). Records which system resolver
# macOS was using and whether its DNS was likely encrypted.
#
# Why it matters: the method reads DNS answers off the wire. macOS 14+ follows
# Discovery of Designated Resolvers (RFC 9462): when the configured resolver
# advertises an encrypted endpoint (8.8.8.8, 1.1.1.1 and 9.9.9.9 all do),
# mDNSResponder silently switches to DoH/DoT and no answer is visible. A run
# like that measures nothing about DNS correlation, so every manifest says so.
#
# resolver_probe sets:
#   RESOLVER            nameservers of the default resolver (scutil --dns)
#   RESOLVER_DDR        yes | no | unknown  - a nameserver advertises DDR
#   RESOLVER_ENCRYPTED  yes | likely | no | unknown
#                       yes    = mDNSResponder holds :443/:853 sockets (root only)
#                       likely = DDR advertised, so macOS upgrades
#
# Call it before flushing DNS and before starting a capture: the DDR query and
# the test lookup are themselves DNS traffic.

resolver_nameservers() {
	scutil --dns 2>/dev/null | awk '
		/^DNS configuration \(for scoped/ { exit }
		/^resolver #/ { n++; next }
		n == 1 && /nameserver\[[0-9]+\]/ { print $3 }' | tr '\n' ' ' | sed 's/ *$//'
}

resolver_ddr() { # nameserver...
	_any=unknown
	for _ns in "$@"; do
		_out="$(dig +short +time=2 +tries=1 "@$_ns" _dns.resolver.arpa TYPE64 2>/dev/null)" || continue
		case "$_out" in
		";;"*) continue ;; # dig reports a timeout on stdout
		"") _any=no ;;
		*)
			echo yes
			return
			;;
		esac
	done
	echo "$_any"
}

resolver_probe() {
	RESOLVER="$(resolver_nameservers)"
	[ -n "$RESOLVER" ] || RESOLVER=unknown
	# shellcheck disable=SC2086 # one argument per nameserver
	RESOLVER_DDR="$(resolver_ddr $RESOLVER)"
	RESOLVER_ENCRYPTED=unknown
	case "$RESOLVER_DDR" in
	yes) RESOLVER_ENCRYPTED=likely ;;
	no) RESOLVER_ENCRYPTED=no ;;
	esac
	if [ "$(id -u)" = 0 ]; then
		dscacheutil -q host -a name example.com >/dev/null 2>&1 || true
		if lsof -nP -a -c mDNSResponder -i :443 2>/dev/null | grep -qE 'TCP|UDP' ||
			lsof -nP -a -c mDNSResponder -i :853 2>/dev/null | grep -qE 'TCP|UDP'; then
			RESOLVER_ENCRYPTED=yes
		fi
	fi
}

# resolver_manifest_fields prints the probe as JSON object members, each line
# ending in a comma, for splicing into a manifest.
resolver_manifest_fields() {
	printf '  "resolver": "%s",\n  "resolver_ddr": "%s",\n  "resolver_encrypted": "%s",\n' \
		"$RESOLVER" "$RESOLVER_DDR" "$RESOLVER_ENCRYPTED"
}
