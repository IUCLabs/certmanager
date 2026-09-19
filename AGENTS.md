# AGENTS.md

## Project Overview

`certmanager` issues Vault PKI certificates for Puppet-managed nodes. It is a
drop-in replacement for the Python `certmanager` script that
`profiles::helpers::certmanager` used to render into a venv.

## The contract

`profiles::pki::vault` (puppet-prod) calls the binary during catalog
compilation:

```
/usr/local/bin/certmanager <fqdn> --alt-names "host,fqdn" --ip-sans "127.0.0.1,<ip>" --expiry-days 90 --json
```

`generate()` runs with `failonfail: true, combine: true`. `combine: true` dups
stderr onto stdout at spawn, so anything on stderr is spliced into the JSON
stream and `parsejson()` fails — breaking the compile with a parse error rather
than a clean failure. Two rules follow:

- the success path writes the JSON document to stdout and nothing to stderr
  (`TestRunSuccessWritesNothingToStderr` guards this);
- every failure exits non-zero, with the message on stderr and stdout empty.

## Structure

```
cmd/certmanager/main.go       # CLI (flattened: the positional arg is the command)
cmd/certmanager/main_test.go  # end-to-end tests against an httptest Vault stub
test/integration/             # end-to-end tests against a real Vault dev server
internal/config/              # YAML config: parsing, defaults, validation
internal/pki/                 # issue + ca_chain requests and the output shapes
internal/vault/               # HTTP client: approle, kubernetes, unauthenticated
Makefile                      # build / test / lint / completions / version bump
.goreleaser.yaml              # single release driver: binaries + RPM + Gitea release
scripts/integration-test.sh   # runs the integration test against a Vault dev server
.woodpecker/                  # CI: build, test, integration, pre-commit (PR) + release (tag)
dist/                         # build output: binaries, RPM, checksums (not committed)
```

## Code Patterns

- **`run(args, stdout, stderr) int`** is the testable entry point; `main()` only
  wires it to the real streams and `os.Exit`. Cobra runs with `SilenceUsage` and
  `SilenceErrors` so nothing reaches stderr unless the run failed.
- **Flat CLI**: the root command takes `common_name` positionally
  (`cobra.ExactArgs(1)`). `ca`, `completion` and `help` are the only
  subcommands; `--config` is persistent so `ca` shares it.
- **`ca` is unauthenticated**: `GET {addr}/v1/{mount}/ca_chain` sends no
  `X-Vault-Token` and loads the config through `config.LoadCA`, which requires
  only `vault.addr`. The body is parsed as PEM, never sniffed — Vault labels it
  `application/pkix-cert`. It prints raw PEM: Puppet uses it as file content.
- **`parseList`** splits comma lists, trims whitespace, drops empty tokens.
- **`config.Load`** applies defaults (`auth_method: approle`, `jwt_path`) then
  `Validate()`, which names the offending key and rejects an unknown
  `auth_method` before any network call.
- **`vault.New`** authenticates once and never falls back between auth methods.
  Every request is bounded by `vault.timeout` (default 30s) — the Python set no
  timeout, so a black-holed Vault hung the whole catalog compile.
- **`config.defaultPath`** is baked in at build time via
  `-X ...internal/config.defaultPath=` (`make build CONFIG_PATH=...`).

## Deliberate deviations from the Python script

- The CA is served by `certmanager ca` from the mount's `/ca_chain`, not welded
  to issuance. `issuing_ca` is the intermediate only, and deriving the CA from
  an issue response would pin CA rotation to each node's 90 day renewal.
- `full_chain` is leaf first; the Python put the issuer first.
- `output_path` is read from under `vault:` where it is actually written. The
  Python declared it at the top level but read it from the unwrapped `vault`
  dict, so it never resolved.
- HTTP timeouts on every request.
- `tls_skip_verify` is a config key defaulting to `true`, preserving the
  Python's `verify=False` while letting it be flipped without a code change.
- Non-zero exit on every failure path.
- `ldap` and `token` auth methods are gone; only `approle` and `kubernetes`
  exist.

## Testing

```bash
make test              # go test -v -race ./...
make integration-test  # -tags=integration, against a real Vault dev server
```

Unit tests stub Vault with `httptest.NewTLSServer` — no live Vault is required.
Coverage: the golden `--json` stdout document, stderr emptiness on success,
rejected logins for both auth methods, missing/empty JWT, unknown
`auth_method`, a non-200 issue response, request timeout, TLS verification when
enabled, file and zip output, and the comma-list parsing table.

`test/integration` (build tag `integration`) provisions a real PKI mount,
policy and `bind_secret_id: false` approle role on a Vault dev server, then
runs the binary with Puppet's argv and asserts exit code, empty stderr, the
four JSON keys, the parsed X.509 CN/SANs/lifetime, and that a refused name
exits non-zero with empty stdout. Dev mode is plain HTTP, so it does not
exercise the TLS path.

## Gotchas

- Changing the JSON key set or key order breaks `parsejson()` in
  `profiles::pki::vault`; `TestRunJSONGolden` pins the exact bytes.
- `alt_names` and `ip_sans` are always sent, as empty strings when unset, to
  match what the Python posted.
- The RPM owns `/usr/local/bin/certmanager` as a symlink; the Puppet class that
  manages that path must be retired in the same change that ships the RPM.
