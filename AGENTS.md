# AGENTS.md

## Project Overview

File Download Agent (FDA) -- a Go HTTP server that proxies file downloads from remote URLs,
serves local files, exposes a WebDAV server, and generates encrypted download links.
Module path: `github.com/junlongzzz/file-download-agent`. Go version: `1.27` (see `go.mod`). App version: `2.1.1` (see `common/version.go`).

## Build / Run / Test Commands

```bash
# Build (preferred)
task build                  # Runs go mod tidy, then builds ./out/fda (fda.exe on Windows)

# Manual build
CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o ./out/fda .

# Run
task run                    # Builds then runs on 127.0.0.1:18080
./out/fda -host=127.0.0.1 -port=18080

# Test
go test ./...                                 # Run all tests
go test ./common/                             # Run tests in a single package
go test ./handler/ -run TestDownload          # Run a single test by name
CGO_ENABLED=1 go test -v -race ./...          # Verbose with race detector (requires cgo)

# Format / Vet
gofmt -w .                  # Format all files
go vet ./...                # Static analysis

# Docker
docker build -t file-download-agent .
```

## Project Structure

```
main.go              # Entry point: flag/env parsing, route registration, server startup
common/
  common.go          # Utilities: MD5, byte formatting, real IP extraction
  crypto.go          # AES-256-GCM encryption (Argon2id KDF)
  version.go         # Semantic version constants
handler/
  download.go        # Download proxy handler (GET=download, POST=link generation)
  ratelimit.go       # Per-client auth failure limiter
  ssrf.go            # SSRF protection (target IP checks and restricted dialer)
  static.go          # Embedded static file server
  webdav.go          # WebDAV handler with Basic Auth
static/              # Embedded single-page UI (vanilla JS, no build step)
  index.html         # Download link generator + WebDAV info
files/               # Default download directory (runtime-created)
Taskfile.yml         # Task runner config (build, run)
Dockerfile           # Multi-stage Docker build
.github/workflows/
  docker.yml         # CI: multi-arch Docker build on semver tag push
```

## Architecture

### Startup and configuration (`main.go`)

`main()` reads `FDA_*` env vars, registers same-named flags (flags override env), configures
`slog`, creates the handlers, starts the server in a goroutine, then blocks on
`SIGINT`/`SIGTERM`.

- If `-dir`/`FDA_DIR` is empty, the download directory is `files` **next to the executable**,
  not `./files` relative to the current working directory. The directory is created with
  `os.MkdirAll` whether it came from the default or was set explicitly.
- `-webdav-dir` defaults to the download directory and is created with `os.MkdirAll` when
  WebDAV is enabled; `-webdav-user` defaults to `anonymous`; `-webdav-pass` defaults to
  `signKey`, or to a random password when `signKey` is also empty. The random password is
  written directly to stderr (not through `slog`) so it remains visible regardless of
  `-log-level`, but it changes on every restart — set `-webdav-pass`/`-sign-key` in production.
  WebDAV authentication cannot be turned off; disable the server with `-webdav-enable=false`.
- The HTTP server sets `ReadHeaderTimeout` and `IdleTimeout` (but not `WriteTimeout`, to avoid
  truncating large downloads) and shuts down gracefully via `http.Server.Shutdown` on signal.
- `-forward-request-headers`/`FDA_FORWARD_REQUEST_HEADERS` and
  `-forward-response-headers`/`FDA_FORWARD_RESPONSE_HEADERS` are comma-separated lists of
  extra headers added to the request/response whitelists. Names are trimmed and canonicalized
  (case-insensitive); there is no automatic request→response pairing. Defaults to none.
- `-allow-private-network`/`FDA_ALLOW_PRIVATE_NETWORK` defaults to `false`. Enabling either
  option logs a warning; forwarding headers without `signKey` warns about credential relay.
  Boolean env values accept `true/false`, `yes/no`, `on/off`, and `1/0` (case-insensitive);
  unrecognized values are ignored with a warning instead of being parsed as false.
- TLS is enabled only when both `-cert-file` and `-cert-key-file` are set. `http.Protocols`
  enables HTTP/1.1, TLS HTTP/2, and h2c simultaneously.
- Static pages are embedded with `//go:embed static/*`, so the binary does not need `static/`
  at runtime.

### Routes (`http.ServeMux`)

| Path        | Handler           | Purpose                                                        |
|-------------|-------------------|----------------------------------------------------------------|
| `/`         | `StaticHandler`   | Rewrites the path to `/static/...` and serves embedded pages   |
| `/download` | `DownloadHandler` | GET = download; POST = generate an encrypted link              |
| `/webdav/`  | `WebDavHandler`   | WebDAV server (registered only when enabled)                   |

### `/download` verification paths (`handler/download.go`)

A GET request is verified in one of two mutually exclusive ways:

1. **Encrypted link**: `?enc=<base64.RawURLEncoding of AES-GCM JSON>`. The payload decrypts to
   `DownloadParams` and is **not** signature-checked. The key comes from the server `signKey`.
2. **Plain query**: `?url=&filename=&expire=&sign=`. When `signKey` is set, the signature is

   ```
   sign = md5(strings.Join([]string{filename?, url, expire?, signKey}, "|"))
   ```

   Optional parameters are appended **only when non-empty**, in that order, with `signKey`
   always last. The client value is lowercased before comparison. Signature checking is
   skipped when `enc` is present or when the server `signKey` is empty. Because `|` is the
   field separator, `filename`, `url`, and `expire` containing `|` are rejected with `400`:
   otherwise moving a field across the separator (e.g. appending `|expire` to `url` and
   omitting `expire`) keeps the signed string identical and bypasses the expiry check.
   Encrypted links are unaffected. A URL that really contains `|` can be signed in its
   canonical `%7C` form (the request then sends `%7C`, which servers decode back to `|`);
   a filename that really contains `|` requires the encrypted-link path.

A POST body is `DownloadParams` JSON (limited to 1 MiB by `http.MaxBytesReader`). In POST, the
`sign` field carries the client-side value of the server's `signKey`, not a signature. The
handler always encrypts with `dh.signKey` so GET can decrypt: when the server sets `signKey`, a
request whose `sign` differs is rejected (JSON `code: 403`); when the server key is empty, the
client value is ignored. The handler clears `sign` before serializing and returns the base64url
blob as the link's `enc` value. `static/index.html` uses this endpoint.

Failed signature checks and failed `enc` decryptions are rate-limited per client (default 10
failures per minute), then `429` with `Retry-After` and no further comparison until the window
expires. Two independent limiters are used: one for guessing the server `signKey` (POST key
checks and plain GET signatures), one for malformed/undecryptable `enc` values. A successful
encrypted or plain signed GET does **not** clear either counter — such links can be shared, so
possession does not prove knowledge of `signKey`; only a successful POST key check resets the
`signKey` limiter. Signature failures therefore cannot lock out valid encrypted downloads.
The `enc` value is capped at 32 KiB before base64 decoding, and the failed-attempt check runs
before the Argon2id KDF. Each client may have at most 16 `enc` decryptions in flight; the slot
is taken before the KDF and released when decoding finishes (not when the file transfer ends),
so a concurrent burst cannot queue unbounded Argon2id work before the failures are recorded.
The global KDF semaphore still caps actual derivations at 4. The key is `common.GetRealIP(r)` (first `X-Forwarded-For` entry, then
`X-Real-IP`, then the TCP peer, truncated to 128 bytes), the same value used in download logs.
`-auth-max-failures`/`-auth-failure-window` tune the limit. The POST key comparison is
constant-time (SHA-256 + `subtle.ConstantTimeCompare`). `GetRealIP` trusts
`X-Forwarded-For`/`X-Real-IP` unconditionally (there is no trusted-proxy allowlist), so a
directly exposed instance can be rate-limit-evaded by spoofing these headers; deploy behind a
proxy that overwrites them.

`expire` is a Unix timestamp in seconds (expired → 403). `url` must use the `http`, `https`,
or `file` scheme. When `filename` is empty and the target is remote, the handler first takes the
filename from the upstream `Content-Disposition`, then falls back to the URL path basename, the
hostname, and finally `download`. For local files the path basename is used. `/`, `.` and `..`
are never used as filenames, and all filenames (user-supplied, encrypted-link, and upstream)
have control characters removed and are capped at 255 runes.

### Download implementations

- **Remote URL** (`downloadUrl`): GET (or HEAD, when the client sends HEAD) built with
  `r.Context()` (client disconnect cancels), max 20 redirects. Only headers in
  `forwardReqHeaders` are forwarded upstream; the built-in request set is limited to download
  essentials (`Accept-Encoding`, `Range`, `If-Range`, `If-Match`, `If-Unmodified-Since`,
  `If-None-Match`, `If-Modified-Since`, `User-Agent`). `Authorization`, `Cookie`, `Referer`,
  `Origin`, `Accept`, `Accept-Language`, and `Cache-Control` are deliberately **not** forwarded
  by default, since the upstream is chosen by the request; add them with
  `WithForwardRequestHeaders`/`-forward-request-headers`. Response headers are a separate list.
  Only `forwardRespHeaders` are copied back (built-in: `Content-Type`, `Content-Length`,
  `Content-Range`, `Content-Encoding`, `Accept-Ranges`, `Last-Modified`, `Etag`, `Vary`), and
  only after the status is known to be successful — otherwise an upstream `Content-Encoding` would
  make `http.Error`'s plain-text body decode as compressed data. The upstream status code is
  written back explicitly, so `206 Partial Content` is not downgraded to `200`. `304 Not
  Modified` is passed through as-is but still forwards whitelisted cache headers (`ETag`,
  `Last-Modified`, `Vary`, and configured headers such as `Cache-Control`); `416` forwards
  upstream `Content-Range`. `401` forwards `WWW-Authenticate` only when `Authorization` is in
  the forwarded request whitelist (so the client's retried credentials can actually reach the
  upstream) or when the response header is explicitly whitelisted; otherwise the challenge is
  dropped, avoiding a browser auth loop where the retried `Authorization` is never forwarded.
  Custom headers added with
  `WithForwardRequestHeaders` are removed from cross-origin redirect requests, so an upstream
  open redirect cannot leak `X-Api-Key`-style secrets; built-in headers are kept.
  Other non-2xx responses are surfaced as errors. Missing
  `Content-Type` becomes `application/octet-stream`. `Content-Disposition` is built with
  `mime.FormatMediaType`, so non-ASCII filenames use RFC 2231 (`filename*=utf-8''...`); the
  upstream value is not forwarded, but its filename is used as the default when none was
  requested. Body is streamed with `io.Copy`. New passthrough headers must be added to the
  whitelist maps explicitly.
- **Local file** (`url=file://...`): path comes from `url.Parse`'s decoded `Path` (never
  `RequestURI()` + `QueryUnescape`, which would double-decode). The leading slash is stripped
  and `filepath.IsLocal` rejects absolute paths and `..` escapes; the file is then opened
  through `os.OpenRoot(dh.dir)` so the kernel/Go enforces the directory boundary. Directories
  are rejected. Served with `http.ServeContent` (Range/304/HEAD support).
- Both private methods return bytes written, `-1` on failure. On success `ServeHTTP` logs one
  line with URL, filename, size, real IP, and User-Agent.

### SSRF protection (`handler/ssrf.go`)

Remote downloads are SSRF-checked unless `-allow-private-network` is set:

- `checkHostIP` resolves the target (or parses a literal IP) and rejects loopback, private,
  unspecified, link-local (including `169.254.169.254`), multicast, IPv4 broadcast,
  `100.64.0.0/10`, Azure wireserver (`168.63.129.16`), and the IPv6 transition ranges
  (`2002::/16` 6to4, `2001::/32` Teredo, local-use NAT64, `100::/64`). NAT64 addresses in
  `64:ff9b::/96` are not blocked wholesale (that would break IPv6-only networks); their embedded
  IPv4 suffix is checked with the IPv4 rules instead. Non-ASCII hostnames are converted with
  `idna.Lookup.ToASCII` before the lookup, matching what `http.Transport` does when dialing.
  The check runs before each request and again in `CheckRedirect` for every redirect hop.
- The default client's `Transport.DialContext` is replaced with a dialer whose `Control`
  callback re-checks the IP actually being connected to, preventing DNS rebinding between the
  pre-request lookup and the dial.
- When `HTTP_PROXY`/`HTTPS_PROXY` is set, the dial target is the proxy, so the dial-layer check
  is skipped and a warning is logged; protection then relies on the pre-request checks.
- A blocked target returns 403; a DNS failure returns 502. A dial-layer rejection surfaces as
  `errPrivateNetwork` through `errors.Is`, because `*url.Error`/`*net.OpError` unwrap it.

### Encryption (`common/crypto.go`)

`Encrypt`/`Decrypt` derive a 32-byte key with Argon2id (parameters keyed by `version` in
`kdfVersionParams`), then use AES-256-GCM. Payloads are `EncryptedData` JSON
(`version`/`salt`/`nonce`/`cipher`, base64). `Decrypt` validates the decoded salt (16 bytes),
nonce (12 bytes), and ciphertext (at least the 16-byte GCM tag) **before** running the KDF;
AES-GCM panics on a non-12-byte nonce, so this check is mandatory. KDF calls are gated by a
process-wide semaphore (4 concurrent derivations, ~128 MiB peak) to bound CPU/memory use.
Keys are zeroed via `zeroBytes`. To change KDF parameters, add a new version — never modify an
existing one, or previously generated links stop decrypting.

### WebDAV (`handler/webdav.go`)

Wraps `golang.org/x/net/webdav.Handler` with `Prefix: "/webdav"` and an in-memory lock system
(locks are lost on restart). Basic Auth only applies when **both** username and password are
non-empty, and credentials are compared in constant time (both username and password are always
compared, no short-circuit). Credentials are validated **before** the rate-limit check, so
correct credentials pass even while the IP is blocked (shared-IP lockout does not lock out the
legitimate user) and clear the counter. Wrong credentials are rate-limited per client (same
configurable limit and `common.GetRealIP` key as `/download`; default 10 failures/minute →
`429`); requests with no credentials receive the normal `401` challenge and do not count as
failures. `main.go` always supplies a non-empty password —
`signKey` when available, otherwise a random password printed at startup — so authentication is
always on. Use `-webdav-enable=false` to turn the server off entirely.

### Static pages (`handler/static.go` + `static/`)

`StaticHandler` rewrites any path without the `/static` prefix to `/static/<path>` and hands it
to `http.FileServerFS`. No build or bundling step.

`index.html` is a single page containing both the link generator and the WebDAV information;
the URL field has a protocol selector and omits the scheme prefix for `file://` targets. All
CSS and JS are inline, and the page uses no external assets so it works fully offline. Theme
follows `prefers-color-scheme`, can be toggled manually, and the choice is persisted in
`localStorage`.

## Code Style Guidelines

### Language and Formatting

- Go `1.27`, formatted with `gofmt` (tabs, no semicolons).
- CGO disabled (`CGO_ENABLED=0`); binary is fully static.
- Dependencies: `golang.org/x/crypto`, `golang.org/x/net` only (`golang.org/x/text` is an
  indirect dependency of `x/net/idna`, used for IDNA hostname conversion). Minimize external deps.
- Comments in Chinese (Simplified). Exported function godoc starts with function name.

### Imports

Two groups: stdlib first, blank line, then external/internal. Each group sorted alphabetically.

```go
import (
    "fmt"
    "net/http"

    "golang.org/x/crypto/argon2"
    "github.com/junlongzzz/file-download-agent/common"
)
```

### Naming Conventions

| Element              | Convention               | Example                                          |
|----------------------|--------------------------|--------------------------------------------------|
| Packages             | lowercase, single word   | `common`, `handler`                              |
| Files                | lowercase, no separators | `download.go`, `crypto.go`                       |
| Exported types       | PascalCase               | `DownloadHandler`, `EncryptedData`               |
| Unexported vars/funcs| camelCase                | `signKey`, `encKey`, `mustRandomBytes`           |
| Method receivers     | 2-letter abbreviation    | `dh *DownloadHandler`, `wh *WebDavHandler`       |
| Constructors         | `NewXxx` returning `*Xxx`| `NewDownloadHandler(dir, signKey string)`        |
| JSON tags            | snake_case               | `json:"filename,omitempty"`                      |
| Env vars             | `FDA_` + SCREAMING_SNAKE | `FDA_SIGN_KEY`, `FDA_WEBDAV_ENABLE`              |
| CLI flags            | kebab-case               | `-sign-key`, `-webdav-enable`                    |

### Types and Interfaces

- Use concrete struct types; no custom interfaces defined.
- Satisfy stdlib interfaces implicitly (e.g., `http.Handler` via `ServeHTTP`).
- All method receivers are pointer receivers (`*T`).
- Struct fields have inline Chinese comments.
- JSON struct tags on all data transfer structs; use `omitempty` where applicable.
- Use `any` (not `interface{}`) for generic types.

### Error Handling

- Standard Go `if err != nil` pattern.
- Fatal startup errors: `slog.Error(...)` then `os.Exit(1)`.
- HTTP errors: `http.Error(w, msg, statusCode)` then `return`.
- Intentionally ignored errors: use `_ = expr` explicitly; never bare call.
- Unrecoverable errors: `panic(err)`.
- No custom error types. Use `fmt.Errorf(...)` for wrapped errors.
- Zero sensitive byte slices after use (`zeroBytes` in `crypto.go`).

### Logging

- Use `log/slog` exclusively (`slog.Info`, `slog.Error`, `slog.Debug`).
- Never use `fmt.Println` or legacy `log` package for runtime logging.
- Format messages with `fmt.Sprintf` inside slog calls:
  ```go
  slog.Info(fmt.Sprintf("Server is running on %s", addr))
  ```

### Functions and Methods

- Use `func` declarations (not variable-assigned function expressions).
- Constructors: `NewXxx(...) *Xxx` pattern, return pointer-to-struct.
- Group parameters sharing a type: `func server(host string, port int, certFile, keyFile string)`.
- Use anonymous closures for deferred cleanup and goroutines.
- No `init()` functions; all initialization explicit in `main()`.

### HTTP Handlers

- Each handler is a struct implementing `http.Handler` (`ServeHTTP` method). One handler per file.
- Route registration uses `http.ServeMux` in `main.go`.
- Private sub-methods (e.g., `downloadUrl`, `downloadFile`) return `int64` bytes written, `-1` on failure.
- JSON responses: `dh.jsonResponse(w, code, msg, data)`; the HTTP status line matches `code`.
- Header forwarding uses explicit whitelist `map[string]bool` fields, never wildcard copies.

### Security Patterns

- Download URLs verified with MD5-based signatures when `signKey` is set; the comparison uses
  `subtle.ConstantTimeCompare`. Failed checks are throttled per client (default 10/min) to
  resist online guessing. The limiter keys on `common.GetRealIP`, so deploy behind a trusted
  proxy that sets `X-Forwarded-For`.
- Encryption: Argon2id KDF for AES-256-GCM.
- Path traversal prevention via `filepath.IsLocal` plus `os.OpenRoot`.
- Sensitive byte slices zeroed after use.
- Request/response header forwarding uses explicit whitelists; `Authorization` and `Cookie` are
  forwarded only when listed in `WithForwardRequestHeaders`/`-forward-request-headers`.
- SSRF protection: pre-request DNS/IP checks, redirect checks, and a dial-layer IP check.
- WebDAV is protected by default authentication; POST bodies are additionally limited by
  `http.MaxBytesReader`. WebDAV PUT bodies have no size limit of their own.

### Configuration

- Environment variables (`FDA_*`) provide defaults; CLI flags override them.
- Default port: `18080`. Default download dir: `files` next to the executable.
- WebDAV enabled by default; disable with `-webdav-enable=false`.
- `-auth-max-failures`/`FDA_AUTH_MAX_FAILURES` (default 10) and
  `-auth-failure-window`/`FDA_AUTH_FAILURE_WINDOW` (default 1m) tune the failed-auth limiter.
  Both `/download` and WebDAV key on `common.GetRealIP(r)`, so run behind a trusted reverse
  proxy that sets `X-Forwarded-For`; otherwise every request is keyed by its TCP peer address.
- Server supports h2c (unencrypted HTTP/2) alongside HTTP/1.1 and TLS HTTP/2.

## CI/CD

GitHub Actions (`.github/workflows/docker.yml`): triggers on semver tag push (`v*.*.*`) or
manual dispatch. Builds a multi-platform Docker image (`linux/amd64`, `linux/arm64`) and pushes
it to DockerHub.

The version is hardcoded in `common/version.go` (`versionX/Y/Z`) and printed by `-version`
together with Go version and OS/arch. Bump it before tagging, and keep the tag name in sync.