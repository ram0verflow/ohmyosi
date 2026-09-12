# Local control threat model

The daemon runs as root to capture macOS traffic. Its HTTP listener defaults to
loopback. Observation and mutation have different authority requirements:
reading the local event stream is part of the current viewer contract, while
changing rules, loading a blocklist, enabling `pf`, or changing MAC/hostname
must require an explicit control capability.

| Client | May inspect? | May mutate? | Mechanism |
| --- | --- | --- | --- |
| Native viewer with no token | Yes | No | No Bearer capability. |
| Native viewer with pasted current token | Yes | Yes | Root-only token file, in-memory Bearer header. |
| Other unprivileged local process | Yes | No, absent token | Cannot read the root-only token file. |
| Cross-origin browser page | No readable CORS response | No | No wildcard CORS; mutation also checks Origin, Host and token. |
| Root process | Yes | Yes | Root can read the token file and already controls the machine. |

The token is generated anew on each root daemon run, stored in a `0700`
directory as a `0600` file, and removed on orderly exit. The path is printed,
never the token. The native app keeps a pasted token in memory only. HTTP
mutation endpoints require a local Host, a same-origin request when Origin is
present, the exact Bearer capability, and the appropriate method. Empty token
configuration fails closed.

The tests use three independent negative conditions: missing or wrong token,
host rebinding and hostile Origin. They verify that no mutation hook runs and
that a viewer can still inspect without unlocking. The macOS build and Go test
suite run in CI. The follow-up manual validation is to launch the daemon with
`sudo`, verify the token file permissions and rotation, try an unauthenticated
local `curl` against every mutation, then unlock in the native app and test one
benign rule add/remove. Run a browser-origin probe separately because browser
private-network policies vary.

This is an interim boundary, not a complete local privacy policy. A process
that already runs as root can read the capability. An attacker who obtains the
token from the operator or an authorized client's memory can use it until the
daemon restarts. Read-only endpoints remain available to other local clients;
protecting those observations is the next threat-model decision. The final
product may replace manual token entry with a narrowly scoped privileged
helper and operating-system authorization without changing the read-side
evidence model.
