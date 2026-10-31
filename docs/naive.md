# Naive outbound

This fork integrates [Ember-Moth/cronet-go](https://github.com/Ember-Moth/cronet-go), derived from SagerNet/cronet-go and using mihomo's `github.com/metacubex/sing` types. Go 1.24 or newer is required. Naive uses Chromium's TLS and HTTP stack, including Naive padding and connection reuse.

## Configuration

```yaml
proxies:
  - name: naive
    type: naive
    server: proxy.example.com
    port: 443
    username: user
    password: password
    # sni: proxy.example.com
    # quic: false
    # quic-congestion-control: cubic # bbr, bbr2, cubic, reno; requires quic
    # stream-receive-window: 134217728 # bytes; 0 uses Cronet's defaults
    # quic-session-receive-window: 15728640 # bytes; requires quic
    # insecure-concurrency: 1
    # headers:
    #   X-Custom-Header: value
    # certificate: ./root-ca.pem # trusted CA PEM or path, NOT a client certificate
    # ech-opts:
    #   enable: true
    #   config: BASE64_ECH_CONFIG_LIST # omit to query HTTPS DNS records
    #   query-server-name: proxy.example.com
    # udp-over-tcp: true # requires a server supporting sing-box UoT
    # udp-over-tcp-version: 2 # 1 or 2; default 2
    # dialer-proxy: another-outbound
    # interface-name: eth0
    # routing-mark: 1234
    # ip-version: ipv4
```

HTTP/2 is the default. `quic: true` selects HTTP/3/QUIC to the proxy server; it does not enable arbitrary UDP forwarding. `udp-over-tcp: true` enables UoT and advertises UDP support. Setting `udp: true` without UoT is rejected. Ordinary Caddy/Naive servers do not necessarily implement the sing-box UoT extension.

`server` is the actual endpoint and `sni` controls the TLS hostname. Proxy DNS uses mihomo's proxy-server resolver (including hosts overrides), bypassing application Fake-IP. The `ipv4`/`ipv6` restrictions are applied to DNS answers. With both families enabled, Chromium controls connection racing; `ipv4-prefer`/`ipv6-prefer` do not override Chromium's own family selection. QUIC through `dialer-proxy` requires that upstream outbound to support UDP.

TLS is always enabled. `skip-cert-verify`, `client-fingerprint`, `fingerprint`, `name-cert-verify`, `private-key`, and `alpn` are unsupported and rejected. Chromium uses its own certificate verifier; mihomo's global Go certificate pool and NTP-adjusted TLS clock are not injected. Use the node's `certificate` field to supply a private CA. Paths follow mihomo's configuration-directory and safe-path rules. Certificate changes take effect when the outbound is recreated.

Headers cannot replace Naive authentication, padding, CONNECT authority, or internal Cronet control fields. Multiple tunnel connections (`insecure-concurrency` greater than 1) alter the traffic profile; the default is one.

## Build

```sh
make naive
```

The output is placed in `bin/naive/<os>-<arch>/`. The script supports Linux/Windows amd64 and arm64 using `with_naive,with_purego`, and macOS amd64/arm64 using `with_naive` and CGO. It also includes `with_gvisor`.

For example, cross-compile Windows on another host:

```sh
GOOS=windows GOARCH=amd64 bash scripts/build-naive.sh
```

Linux and Windows builds must ship **both** the executable and the accompanying `libcronet.so`/`libcronet.dll`. `with_purego` removes the CGO build requirement, not the native runtime dependency. The fork's bindings and `cronet-go/all` are pinned together in `go.mod`. Its `all` module reuses the ABI-matched SagerNet native library modules, without importing SagerNet's Go bindings or `sing`; the script downloads that pinned native revision. Do not substitute a library from an unrelated release. The script requires Python 3 to read Go's module download metadata.

macOS requires Xcode's command-line tools and links the library statically:

```sh
CGO_ENABLED=1 go build -tags with_gvisor,with_naive
```

For native Linux (including musl) and Android/iOS builds, follow the [cronet-go toolchain instructions](https://github.com/SagerNet/cronet-go#downstream-build-requirements) and add `with_naive` to your existing tags. Linux CGO builds require the Chromium toolchain; musl additionally requires `with_musl`. Android needs the NDK and Apple targets need Xcode. Availability and minimum OS/libc versions are constrained by the pinned native library, rather than mihomo's ordinary build matrix.

Ordinary builds without `with_naive` keep native dependencies out of the executable. Parsing a Naive node then reports the missing build tag. `mihomo -v` lists `with_naive` when compiled in. The existing general release workflow builds these ordinary binaries; the separate Naive workflow uploads the complete Naive bundles.

## Tests

Configuration tests run without native libraries. DNS and adapter tests can run with `with_naive,with_purego` without creating a native client. Real interoperability tests use an explicitly supplied sing-box binary, start local HTTP/2 and QUIC servers, and exercise TCP, UoT, authentication, TLS verification, and shutdown:

```sh
NAIVE_TEST_SERVER=/absolute/path/to/sing-box \
  CGO_ENABLED=1 go test -tags with_naive ./adapter/outbound -run Naive -count=1
```

For purego builds, add `with_purego` and set `CGO_ENABLED=0`. Put the matching library on `LD_LIBRARY_PATH` (Linux) or `PATH` (Windows); `go test` executes from a temporary directory. Without `NAIVE_TEST_SERVER`, interoperability tests are skipped. No external proxy credentials or public endpoints are needed.
