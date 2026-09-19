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
internal/config/              # YAML config: parsing, defaults, validation
internal/pki/                 # issue request/response + the JSON output shape
internal/vault/               # authenticated HTTP client (approle, kubernetes)
Makefile                      # build / test / lint / completions / rpm / version bump
packaging/nfpm.yaml           # nfpm spec (envsubst-templated) for the RPM
scripts/build-rpm.sh          # generates completions + packages the RPM
.woodpecker/                  # CI: build, test, pre-commit (PR) + release (tag)
dist/                         # build output: binary, completions, RPM (not committed)
```

## Code Patterns

- **`run(args, stdout, stderr) int`** is the testable entry point; `main()` only
  wires it to the real streams and `os.Exit`. Cobra runs with `SilenceUsage` and
  `SilenceErrors` so nothing reaches stderr unless the run failed.
- **Flat CLI**: the root command takes `common_name` positionally
  (`cobra.ExactArgs(1)`). Only `completion` and `help` are subcommands.
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

- Emits `ca_certificate`; the Python did not, so Puppet's
  `/etc/pki/tls/vault/ca_certificate.crt` was silently never populated.
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
make test           # go test -v -race ./...
```

Vault is stubbed with `httptest.NewTLSServer` — no live Vault is required.
Coverage: the golden `--json` stdout document, stderr emptiness on success,
rejected logins for both auth methods, missing/empty JWT, unknown
`auth_method`, a non-200 issue response, request timeout, TLS verification when
enabled, file and zip output, and the comma-list parsing table.

## Gotchas

- Changing the JSON key set or key order breaks `parsejson()` in
  `profiles::pki::vault`; `TestRunJSONGolden` pins the exact bytes.
- `alt_names` and `ip_sans` are always sent, as empty strings when unset, to
  match what the Python posted.
- The RPM owns `/usr/local/bin/certmanager` as a symlink; the Puppet class that
  manages that path must be retired in the same change that ships the RPM.
