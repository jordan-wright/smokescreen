# Smokescreen passive TLS and SSH telemetry — experiment report
Date: 2026-11-06
Prepared for Jordan

## Decision
Use a bounded passive observer in Smokescreen's existing CONNECT connection wrapper. This can recover server-selected TLS version, cipher suite and TLS 1.3 key-exchange group without terminating TLS, including X25519MLKEM768. TLS 1.2 ECDHE groups require parsing ServerKeyExchange. Initial SSH offers permit algorithm-selection inference; SFTP itself is encrypted and cannot be identified from this vantage point.

The working prototype validates feasibility. It is an experiment, not a production-ready parser or an enforcement mechanism. It adds no network round trips or read-ahead, but it does synchronous CPU work on the forwarding path.

## Environment and preserved work
- Sprite: codex-smokescreen-wire-observer
- Smokescreen repository: /home/sprite/smokescreen
- Upstream base: 5b4b7aabca9bc70a8435358d648edd03294c299e
- Branch: experiment/wire-observer
- Go: go1.27.3 linux/amd64; module targets Go 1.26.
- Executable: /home/sprite/smokescreen-experimental
- Separate SSH/SFTP harness: /home/sprite/wirelab
- Harness dependencies: golang.org/x/crypto v0.58.0 and github.com/pkg/sftp v1.13.12. No new production dependencies.
- Checkpoint v2 preserves the first passing TLS experiment before adding harness dependencies. The final checkpoint is reported in the conversation.
- No remote repository push or deployment was performed.

## What the wire reveals
| Attribute | TLS 1.2 | TLS 1.3 | Initial SSH |
|---|---|---|---|
| Protocol version | ServerHello | ServerHello supported_versions; legacy version is misleading | Identification banner |
| Selected cipher | ServerHello; suite also identifies key-exchange/auth family | ServerHello; suite describes AEAD/hash, not key exchange or authentication | Inferred from both KEXINIT lists, separately per direction |
| Key exchange | Suite family; ECDHE named group in ServerKeyExchange; DHE needs separate parameter handling | ServerHello key_share group; pre_shared_key indicates selected PSK; PSK-only can have no group | Inferred KEX from both initial offers |
| Client offers | Cipher suites, groups, signature algorithms, ALPN, version indicators | Same, plus initial key-share groups; ECH can hide inner offers | KEX, host-key, cipher, MAC, compression lists |
| Server capabilities | Selection is evidence of that choice, not a complete capability list | Same; server supported_groups extension is encrypted | Server advertises initial algorithm lists for this connection |
| Selected ALPN | Plaintext ServerHello extension | EncryptedExtensions: unavailable passively | Not applicable |
| Server certificate / authentication signature | Often visible on full handshakes; omitted on resumption | Encrypted | Host key/signature can be parsed from KEX replies with algorithm-specific handling |
| Completed authenticated handshake | Cannot prove it passively | Cannot prove it passively | Cannot prove it passively |
| SFTP activity / filenames / user | Not applicable | Not applicable | Encrypted; unavailable |

The prototype implements version, cipher, ECDHE/TLS 1.3 group, first client capability lists, ALPN where visible, HRR indication, server PSK selection, ECH-extension presence, SSH banners/offers and modern SSH selection inference. Certificate parsing, SNI, detailed handshake signatures, DHE parameters and SSH host-key fingerprints are intentionally outside this experiment.

Offers mean “advertised on this connection,” not the endpoint's entire installed capabilities. A server choosing X25519 does not prove it lacks hybrid KEX; the client's offer or server policy may explain the choice. A server choosing hybrid does demonstrate that selection in this exchange.

ECH permits observation of the outer ClientHello, not recovery of the inner ClientHello. Extension presence does not prove ECH acceptance; GREASE can produce an ECH-looking offer. ServerHello remains observable. A future production schema should explicitly label client offer visibility as outer/clear rather than claiming a complete client capability inventory.

TLS 1.2 resumed handshakes have no fresh ServerKeyExchange. Preserve the selected suite but leave the group unavailable; do not copy an assumed group from another connection. TLS 1.3 PSK selection is not proof of successful resumption, and an external PSK is also possible. Neither PSK selection nor application-data-shaped records proves authentication succeeded.

## Integration and log semantics
Changes:
1. Config.ObserveTunnelHandshake and --observe-tunnel-handshake, disabled by default.
2. Initialize an observer on the existing CONNECT InstrumentedConn.
3. Observe successful bytes from outbound Write as client-to-server and Read as server-to-client.
4. Append structured fields to CANONICAL-PROXY-CN-CLOSE, retaining the existing connection id.
5. Existing parser-free behavior remains the default.

Files:
- cmd/smokescreen.go
- pkg/smokescreen/config.go
- pkg/smokescreen/smokescreen.go
- pkg/smokescreen/conntrack/instrumented_conn.go
- pkg/smokescreen/conntrack/wire_observer.go
- pkg/smokescreen/conntrack/wire_observer_test.go
- pkg/smokescreen/wire_integration_test.go
- pkg/smokescreen/wire_passthrough_test.go

The initial proxy-decision log happens before the tunneled handshake, so it cannot contain future selections. Close logs are the smallest change. Long-lived tunnels may require a separate once-per-connection handshake-observed event linked by id; that was not implemented.

Example fields from the real TLS 1.3 hybrid run, extracted from its close log:
```json
{
  "msg": "CANONICAL-PROXY-CN-CLOSE",
  "wire_evidence": "unauthenticated_initial_handshake",
  "wire_client_supported_versions": ["0x0304"],
  "wire_client_supported_groups": ["0x11ec"],
  "wire_client_key_share_groups": ["X25519MLKEM768"],
  "wire_server_version": "TLS 1.3",
  "wire_server_cipher_suite": "TLS_AES_128_GCM_SHA256",
  "wire_server_key_exchange_group": "X25519MLKEM768",
  "wire_server_key_exchange_group_id": "0x11ec",
  "wire_server_status": "server_hello"
}
```

For production I would prefer a compact schema with explicit selected/offered/inferred naming, numeric algorithm identifiers plus names, parse status, and an unverified-evidence label. No field should imply successful authentication. Unknown IDs must remain representable. GREASE values should be retained as raw offers or explicitly classified, not counted as usable cryptographic capabilities.

## Bounded forwarding design
- No packet capture, extra socket, DNS request, active probe, TLS termination, or additional goroutine per connection.
- Read and write return their original byte counts/errors. Parser failure does not reject traffic.
- Incremental TLS record and handshake reassembly handles arbitrary stream fragmentation.
- 64 KiB cumulative input budget per direction, 128 TLS-record limit, and 10-second elapsed budget checked on new input.
- Once finished, discard raw buffers and use an atomic completed check on subsequent calls.
- Independent direction locks; snapshot fields for close logging.
- Stop TLS client parsing after the first ClientHello. An HRR is recorded and the server's final selection is parsed; the second ClientHello is not recorded.
- No key material, session tickets, PSK binders, raw payloads, or certificate chains are logged.

Important qualifications: the byte budget is not an exact heap cap. Buffer growth, handshake copies, decoded slices, strings and maps add overhead. The time budget does not independently expire an idle connection's buffers; it is checked when input next arrives. Strong per-field/count limits and aggregate memory accounting are required before high-concurrency deployment.

The observer does synchronous work before returning from Read/Write. It does not wait for a full handshake before forwarding; nevertheless, parsing can add microseconds of local scheduling delay. “No added latency” would be an inaccurate claim.

## Experiments and outcomes
| Test | Result |
|---|---|
| Actual Smokescreen CONNECT, TLS 1.2 X25519 | Logged version/cipher/group matched tls.ConnectionState |
| TLS 1.2 P-256 | Matched |
| TLS 1.3 X25519 | Matched |
| TLS 1.3 X25519MLKEM768 | Matched |
| TLS 1.3 HelloRetryRequest to P-256 | Retry and final group matched endpoint state |
| TLS 1.3 PSK resumption with hybrid KEX | Endpoint confirmed DidResume; observer logged PSK selection and group |
| TLS 1.3 client writes fragmented into 7-byte chunks | Request completed; fields matched |
| Every split of synthetic ServerHello across two TLS records, across multiple input chunk sizes | Passed |
| SFTP over CONNECT, curve25519-sha256, aes128-ctr, hmac-sha2-256, Ed25519 host key | 120,000-byte upload and download verified byte for byte; log inference matched constrained configuration |
| SFTP over CONNECT, mlkem768x25519-sha256, aes128-gcm@openssh.com | Same payload verification; hybrid KEX and implicit AEAD MAC correctly logged |
| Compiled CLI with OpenSSL client/server and X25519MLKEM768 | HTTP 200; close log contained hybrid group |
| Unknown protocol, malformed TLS, malformed SSH through real proxy | Payloads over 128 KiB echoed unchanged |
| New observer/integration tests under race detector | Passed |
| SSH/SFTP harness under race detector | Passed |
| Full go test ./... | Passed |
| Focused go vet | Passed |
| Short fuzz smoke test | 184,189 executions reported, no crash; not a comprehensive security assurance |

The Go TLS integration harness uses local test certificates and skips certificate verification to isolate transport behavior; SSH pins the generated host key. All experiment listeners bind loopback or use httptest loopback servers. Short-lived test subprocesses were stopped afterward.

## Performance measurements
Sprite AMD EPYC, Go 1.27.3; these are exploratory measurements.

Microbenchmarks, three runs:
- New observer + synthetic TLS 1.3 ServerHello: 2.34–2.44 microseconds, 1,944 B and 30 allocations.
- Same plus field snapshot: 3.99–4.09 microseconds, 3,129 B and 43 allocations.
- Already-completed observer called with a 32 KiB slice: 2.63–2.87 nanoseconds, zero allocations. This measures the no-op check, NOT memory-copy throughput.

Whole-proxy benchmark, five repetitions of 500 fresh connections per mode:
- CONNECT + TLS 1.3 hybrid + HTTP request/response + close.
- Keep-alive disabled; JSON log formatting included, output discarded.
- Disabled: 3.56–3.81 ms/op, approximately 265–268 KB allocated, 1,274–1,275 allocations.
- Enabled: 3.32–3.63 ms/op, approximately 286–289 KB allocated, 1,416–1,419 allocations.
- Approximately 20–23 KB and 142 extra allocations per connection in this verbose prototype.

The enabled runs appeared faster, but the test order, shared VM scheduling, warmup/drift, and occasional connection-reset-at-teardown warnings make this unsuitable evidence of a speedup or a precise latency bound. Both modes experienced reset warnings. Application payload tests passed. These are averages, not p95/p99 or production load measurements.

The evidence supports a cheap completed fast path. It also identifies allocation and log expansion as the main optimization target. It does not establish a production throughput or tail-latency SLO.

## Smallest production candidate
1. Ship only compact selected TLS version/cipher/group, observation status and optional compact offered groups/versions first.
2. Represent parsed metadata in typed bounded structures, formatting at log emission. Avoid allocating maps and formatted strings throughout parsing.
3. Make full client capability lists and SSH lists separately opt-in or sampled. Do not emit large arrays on every long-lived connection by default.
4. Add strict field-count, string-length and heap limits, duplicate-extension checks, malformed-vector tests and a larger fuzz corpus.
5. Use a narrow opt-in rollout, with counters for malformed/unsupported/limited observations and bounded labels. Never use SNI, arbitrary offers or destinations as unbounded metric labels.
6. Repeat randomized/interleaved benchmarks on representative hardware, including p95/p99, high concurrency, slow/partial hellos, bulk transfers, and real log sinks.

SSH needs more validation before production. Modern KEX negotiation was tested, but exotic legacy KEX/host-key compatibility rules require a stricter implementation. The parser currently expects the SSH banner at the start and KEXINIT as the first binary packet; legal server pre-banner lines and intervening packets are not covered. It excludes ext-info and strict-KEX marker names from selection and treats AEAD MACs as implicit. Encrypted rekeys are invisible.

Smokescreen must actually carry the SSH session via HTTP CONNECT (for example through an SSH ProxyCommand connector). Direct SSH/SFTP traffic bypassing it cannot be observed.

Other scope gaps: chained upstream proxies, Smokescreen MITM mode, inbound TLS to the proxy, nested TLS, STARTTLS, ECH integration, TLS 1.2 resumption/DHE, and QUIC were not validated here. The outbound socket wrapper can see proxy framing or another TLS layer in chained deployments. Production instrumentation needs an explicit “target tunnel established” hook there. If Smokescreen terminates a TLS leg, prefer that leg's crypto/tls ConnectionState and label which leg is being measured.

## Reproduce
Inside the Sprite:
```sh
cd /home/sprite/smokescreen
go test ./...
go test -race ./pkg/smokescreen ./pkg/smokescreen/conntrack -run TestWire
go test ./pkg/smokescreen/conntrack -run '^$' -bench BenchmarkWire -benchmem
go test ./pkg/smokescreen -run '^$' -bench BenchmarkWireProxy -benchtime=500x -count=5
go test ./pkg/smokescreen/conntrack -run '^$' -fuzz FuzzWire -fuzztime=20s -parallel=2
go build -o /home/sprite/smokescreen-experimental .
cd /home/sprite/wirelab
go test -race -v
python3 cli_smoke.py
```

Production CLI opt-in: --observe-tunnel-handshake. The loopback allow-address and allow-self-connections flags in cli_smoke.py are laboratory settings, not deployment recommendations.

Evidence logs are preserved under /home/sprite/smokescreen/experiment-evidence and /home/sprite/wirelab. The library-facing report is a standalone copy of this experiment narrative.

## Primary references
- Smokescreen source: https://github.com/stripe/smokescreen/tree/5b4b7aabca9bc70a8435358d648edd03294c299e
- TLS 1.3, ServerHello and key_share: https://www.rfc-editor.org/rfc/rfc8446.html
- TLS 1.2 handshake: https://www.rfc-editor.org/rfc/rfc5246.html
- TLS 1.2 ECDHE parameters: https://www.rfc-editor.org/rfc/rfc8422.html
- ALPN: https://www.rfc-editor.org/rfc/rfc7301.html
- SSH transport and algorithm negotiation: https://www.rfc-editor.org/rfc/rfc4253.html
- SSH encrypted channels and subsystems: https://www.rfc-editor.org/rfc/rfc4254.html
- ECH: https://www.rfc-editor.org/rfc/rfc9849.html
