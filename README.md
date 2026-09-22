# certmanager

Issues Vault PKI certificates for Puppet-managed nodes. Drop-in replacement for
the Python `certmanager` script deployed by `profiles::helpers::certmanager`,
compiled to a single static binary with no runtime dependencies.

Puppet calls it server-side during catalog compilation from
`profiles::pki::vault`:

```
/usr/local/bin/certmanager <fqdn> --alt-names "host,fqdn" --ip-sans "127.0.0.1,<ip>" --expiry-days 90 --json
```

`generate()` runs the binary with `combine: true`, which splices stderr into the
stdout that `parsejson()` reads — so on the success path the binary writes
nothing but the JSON document to stdout, and nothing at all to stderr. Every
failure path exits non-zero.

## Usage

```
certmanager <common_name> [flags]   # issue a certificate
certmanager ca [flags]              # print the CA chain
certmanager                         # print help
```

The common name is positional, with no `pki` subcommand in front of it — that
is the form Puppet calls, and it is the only issuing form. `ca`, `completion`
and `help` are the subcommands; every other first argument is a common name.

| Flag | Short | Type | Default | Description |
|---|---|---|---|---|
| `--alt-names` | `-a` | comma list | `""` | DNS subject alternative names |
| `--ip-sans` | `-i` | comma list | `""` | IP subject alternative names |
| `--expiry-days` | `-e` | int | `365` | Certificate validity in days (`ttl: <n>d`) |
| `--compress` | `-c` | bool | `false` | Write a zip instead of a directory |
| `--json` | | bool | `false` | Print the certificate data as JSON |
| `--config` | | path | resolved (see below) | Config file location |

`ca` takes `--config` plus:

| Flag | Short | Type | Default | Description |
|---|---|---|---|---|
| `--mount` | `-m` | string | `vault.mount_point` | PKI mount to read |

Comma lists are split on `,`, whitespace-trimmed, and empty tokens dropped.

### JSON output

```json
{
  "certificate": "<PEM leaf>",
  "private_key": "<PEM key>",
  "full_chain": "<certificate PEM>\n<issuing_ca PEM>"
}
```

`full_chain` is leaf first, the order every TLS server expects.

The CA is not part of this document. It is estate-wide and public, so binding
it to a node's issuance would pin CA distribution to that node's renewal cycle;
`certmanager ca` fetches it instead.

### File output

Without `--json` the certificate is written under `vault.output_path`
(defaulting to the working directory):

| Path | Contents |
|---|---|
| `<output_path>/<common_name>/certificate.crt` | Signed certificate |
| `<output_path>/<common_name>/private.key` | Private key (mode 0600) |
| `<output_path>/<common_name>/full_chain.crt` | Certificate + issuing CA |

With `-c` the same three files are written into
`<output_path>/<common_name>.zip`.

## The `ca` subcommand

```
certmanager ca [--mount <pki_mount>] [--config <path>]
```

Prints the mount's CA chain to stdout as raw PEM — not JSON, because Puppet
uses it as file content directly:

```puppet
file { '/etc/pki/tls/vault/ca_certificate.crt':
  content => generate('/usr/local/bin/certmanager', 'ca'),
}
```

It reads `GET {addr}/v1/{mount}/ca_chain` unauthenticated: no AppRole login, no
Kubernetes login, no token header. A config carrying only `addr` and
`mount_point` is enough, and `--mount` overrides the configured mount.

`/ca_chain` returns the intermediate **and** the root, unlike `issuing_ca` or
`/ca/pem`, which return the intermediate alone. An intermediate-only `CAfile`
is not self-sufficient: strict path builders that require a chain to a
self-signed root reject it.

The endpoint advertises `application/pkix-cert` while serving PEM, so the body
is parsed rather than sniffed. A non-200, an empty body or anything that is not
a PEM certificate chain exits non-zero with the cause on stderr and nothing on
stdout.

## Configuration

YAML, everything nested under `vault:`.

### Config resolution order

1. `--config <path>`, which always wins;
2. `$XDG_CONFIG_HOME/certmanager/config.yaml`, if the file exists;
3. `$HOME/.config/certmanager/config.yaml`, if the file exists;
4. `/opt/certmanager/config.yaml`, the path baked in at build time
   (`make build CONFIG_PATH=...`).

Steps 2 and 3 are skipped unless the file is really there, so the last step is
what Puppet gets: `generate()` runs the binary as the `puppet` user with no
usable home directory, and `profiles::helpers::certmanager` writes the config
to `/opt/certmanager/config.yaml` on managed nodes. The k8s puppetserver
compilers mount it at the same path.

| Key | Required | Default | Notes |
|---|---|---|---|
| `addr` | yes | | e.g. `https://vault.example.com:8200` |
| `auth_method` | no | `approle` | `approle` or `kubernetes` |
| `mount_point` | yes | | e.g. `pki_int` |
| `role_name` | iff issuing | | e.g. `my-role` |
| `role_id` | iff `approle` and issuing | | |
| `approle_path` | iff `approle` and issuing | | e.g. `approle` |
| `k8s_mount` | iff `kubernetes` and issuing | | e.g. `kubernetes` |
| `k8s_role` | iff `kubernetes` and issuing | | e.g. `my-certmanager-role` |
| `jwt_path` | no | `/var/run/secrets/kubernetes.io/serviceaccount/token` | |
| `output_path` | no | `.` | Non-JSON output directory |
| `tls_skip_verify` | no | `true` | Set `false` once every node trusts the CA |
| `timeout` | no | `30s` | Per-request Vault timeout |

```yaml
vault:
  addr: https://vault.example.com:8200
  auth_method: approle
  approle_path: approle
  role_id: <role_id>
  mount_point: pki_int
  role_name: my-role
  output_path: /tmp/certmanager
```

`ca` requires only `addr` and a mount; every auth key above is optional for it.

AppRole logs in with `role_id` only — the Vault role sets
`bind_secret_id: false`. Kubernetes reads the JWT from `jwt_path` and posts it
with `k8s_role`. A missing, unreadable or empty JWT, a rejected login, or an
unknown `auth_method` each fail naming the cause; there is no fallback between
methods.

## Development

```sh
make build        # -> dist/certmanager (CGO disabled, static)
make test         # go test -v -race ./...
make lint         # golangci-lint
make pre-commit   # uvx pre-commit run --all-files
make completions       # -> dist/completions/
make integration-test  # end-to-end against a real Vault dev server
make release-snapshot  # goreleaser: binaries, tar.gz and RPM into dist/
```

`make integration-test` starts a `hashicorp/vault` dev container with
docker/podman, provisions a PKI mount and an approle role, then runs the built
binary with the exact argv Puppet uses and asserts on the issued certificate. A
root mount signs an intermediate so the CA chain under test is the two
certificate shape production serves.
Point it at an existing dev server with `CERTMANAGER_IT_VAULT_ADDR`
(`VAULT_ADDR` is deliberately ignored — the test writes to the PKI mount).

## Releasing

goreleaser drives the whole release from a `v*` tag:

- raw binaries `certmanager-<os>-<arch>` (linux/darwin, amd64/arm64) attached to
  the Gitea release — the puppetserver-compiler initContainer fetches one file
  by URL and checksums it, so it cannot unpack an archive;
- `tar.gz` archives and `checksums.txt`;
- `certmanager-<version>-1.<arch>.rpm`, installing `/usr/bin/certmanager`,
  symlinking `/usr/local/bin/certmanager` (the path Puppet calls) and shipping
  bash/zsh/fish completions.

The release pipeline then `PUT`s the RPM to the artifactapi `rpm-internal`
repo, which goreleaser cannot do itself.
