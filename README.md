# sing-vis

A web app that explains **how a [sing-box](https://github.com/SagerNet/sing-box) configuration routes a domain or IP**. Paste a sing-box JSON config, enter a list of domains/IPs, and sing-vis shows — for each one — which DNS rule and route rule it hits, every condition evaluated along the way, and the final DNS server and outbound.

It runs **entirely in your browser**: the matching engine is sing-box's own Go code compiled to WebAssembly. There is no backend, nothing is uploaded, and you can host it as static files (including on GitHub Pages).

![overview](docs-shot.png)

## Quick start

Requires Go (the module targets `go 1.24.7`; the default `GOTOOLCHAIN=auto` fetches a matching toolchain automatically). No Node/npm — the frontend has no build step.

```bash
./run.sh                 # builds the wasm engine, serves http://127.0.0.1:8787
./run.sh 9000            # custom port
./run.sh 0.0.0.0:9000    # custom host:port (expose on your LAN)
```

Open the printed URL. That's it.

## Using it

1. **Paste a config.** The editor opens pre-filled with a sample. Replace it with your own sing-box JSON in the config box (JSONC comments are fine), and give the profile a name.
2. **List what to check.** In *Domains / IPs to check*, put one host per line — domains (`www.google.com`) or raw IPs (`1.1.1.1`). Lines starting with `#` are ignored. Pasted URLs and `host:port` strings are accepted (scheme/path/port are stripped).
3. **Click ▶ Analyze.** The first run downloads the ~3.3 MB wasm engine (cached afterwards). For every input you get:
   - **DNS routing** — which `dns.rules` rule matches, the resulting DNS **server** (or `reject`/other action), and the outbound **detour** that server is reached through.
   - **Route matching** — every `route.rules` rule in order, each condition's result (**match** / no match / **`UNKNOWN?`**), which `rule_set` matched and on which headless rule, down to the **final outbound**.
   - **Resolved IPs** — the A/AAAA records fetched via DoH (shown when a domain is resolved).

   Click any result card to expand it, and any rule step to see its per-condition breakdown.
4. **Save the profile** with 💾. Profiles live in your browser (IndexedDB), persist across reloads, and appear in the left sidebar. Settings persist too. Everything stays on your machine.

### Toolbar options

- **Resolve IPs for IP rules** (on by default) — pre-resolves each domain via DoH so `ip_cidr` and IP rule-set rules match the resolved address, matching what you'd intuitively expect. Turn it off for strict sing-box semantics, where IP rules only match *after* an explicit `resolve` action.
- **network: any / tcp / udp** — an assumed connection network, so rules filtering on `network` can be evaluated.
- **⚙ Settings** — the DoH endpoint (default `https://1.1.1.1/dns-query`).

### Conditions that can't be known offline

Some rule conditions depend on live connection attributes that don't exist for a "what would this domain do?" query — `protocol`, `process_name`, `inbound`, `clash_mode`, source address/port, destination `port`, etc. These show as **`UNKNOWN?`** (amber). If such an undeterminable **terminal** rule sits *before* the definite match, the outcome is flagged **"depends on assumptions"**, because at runtime that rule could preempt the result.

### Rule sets

- **inline** — read straight from the config.
- **remote** — fetched live from its `url` (source `.json` or binary `.srs`, auto-detected). The URL must allow CORS (GitHub raw does).
- **local** — the browser can't read disk paths, so upload the file under *Local rule-set files* in the editor, keyed by the rule-set **tag** or its **path**. `.srs` is read as binary; anything else as source JSON.

## Why it's faithful

Rather than re-implement sing-box's matching, sing-vis **imports sing-box's own Go packages** for the version-sensitive parts:

- `option` — parses the config with sing-box's real unmarshalers (rule/action/rule-set dispatch, JSONC).
- `common/srs` — reads the binary `.srs` format (compiled domain succinct-sets and IP sets).
- `sing/common/domain` — the actual succinct-set domain/suffix matcher (the same code `route/rule.DomainItem` wraps).

sing-vis owns only the **orchestration** — AND across fields / OR within a field's array / logical `and`·`or` / `invert`, first-terminal-match-wins, the `resolve → ip_cidr` lifecycle, and the `final` fallback — so it can **instrument** every step and report exactly which condition and rule-set matched.

> The engine deliberately does **not** import sing-box's `adapter` / `route/rule` packages: they pull in the full outbound/dialer/sing-tun tree, which doesn't compile for `wasm`. The only rule fields needing a connection context are `domain` / `network` / `query_type` — the domain matcher is called directly on `sing/common/domain` (identical to `route/rule.DomainItem`), and network / query_type are plain membership tests. See `internal/engine/conditions.go`.

## Building & hosting

`./run.sh` is just `./build.sh` followed by a static file server. To build and serve separately:

```bash
./build.sh                          # -> web/singvis.wasm (+ .gz) and web/wasm_exec.js
python3 -m http.server -d web 8787  # or any static server
```

After `build.sh`, the `web/` directory is completely self-contained. To publish on **GitHub Pages**, serve `web/` (commit it, or copy it to a `gh-pages` branch / `docs/` folder). The built `web/singvis.wasm`, `web/singvis.wasm.gz`, and `web/wasm_exec.js` are generated artifacts (gitignored); regenerate them any time with `./build.sh`.

### The wasm build overlay

Three files in the `sing` dependency (`common/buf/buffer_unix.go`, `common/bufio/vectorised_unix.go`, `common/bufio/copy_direct_posix.go`) reference `golang.org/x/sys/unix`, which has no `GOARCH=wasm` equivalent. Those code paths (raw-socket `readv`/`writev`) never run in a browser. `build.sh` swaps them for wasm-safe stubs in `wasmbuild/_stubs/` via `go build -overlay` (generated by `wasmbuild/gen-overlay.sh`). **Only the wasm build uses the overlay** — native builds and `go test` are unaffected.

## Testing

The engine is platform-agnostic and tested natively (no wasm needed):

```bash
go test ./internal/engine
```

## CORS

DoH resolution and remote rule-set fetches originate from the browser, so those endpoints must send `Access-Control-Allow-Origin`. The defaults do — Cloudflare/Google DoH JSON (`https://1.1.1.1/dns-query`, `https://dns.google/dns-query`) and `raw.githubusercontent.com`. Point sing-vis at an endpoint that doesn't, and that item shows a fetch error; swap it for a CORS-enabled one, or upload the rule-set file locally. The resolver uses the DoH **JSON API** (`?name=&type=&ct=application/dns-json`), a CORS "simple request" that avoids a preflight.

## Project layout

```
cmd/wasm/          js/wasm entry point: exposes singvisAnalyze() to JS
internal/engine/   the matching engine (platform-agnostic, unit-tested)
  parse.go           config → option structs (route/dns rules, rule sets, servers)
  conditions.go      per-condition tri-state evaluation (match/no_match/unknown)
  rules.go           field extraction + logical-rule recursion
  ruleset.go         inline/remote/local rule-set loading (incl. .srs binary) + eval
  route.go           route-rule orchestration (actions, resolve, final)
  dns.go             dns-rule orchestration (actions, dns.final, server → detour)
  analyze.go         top-level per-input driver
internal/dnsx/     DoH (JSON API) resolver
web/               static single-page frontend (no build step)
  index.html         markup
  app.js             UI + rendering
  storage.js         profiles & settings in IndexedDB
  worker.js          Web Worker: loads the wasm engine, runs analyze off the UI thread
wasmbuild/         wasm build support (overlay generator + unix→wasm stubs)
sing-box/          upstream sing-box clone (imported via a go.mod replace)
```
