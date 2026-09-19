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
certmanager <common_name> [flags]
```

| Flag | Short | Type | Default | Description |
|---|---|---|---|---|
| `--alt-names` | `-a` | comma list | `""` | DNS subject alternative names |
| `--ip-sans` | `-i` | comma list | `""` | IP subject alternative names |
| `--expiry-days` | `-e` | int | `365` | Certificate validity in days (`ttl: <n>d`) |
| `--compress` | `-c` | bool | `false` | Write a zip instead of a directory |
| `--json` | | bool | `false` | Print the certificate data as JSON |
| `--config` | | path | `/opt/certmanager/config.yaml` | Config file location |

Comma lists are split on `,`, whitespace-trimmed, and empty tokens dropped.

### JSON output

```json
{
  "certificate": "<PEM leaf>",
  "private_key": "<PEM key>",
  "full_chain": "<issuing_ca PEM>\n<certificate PEM>",
  "ca_certificate": "<issuing_ca PEM>"
}
```

`ca_certificate` is new. `profiles::pki::vault` writes
`$cert_data['ca_certificate']` to `/etc/pki/tls/vault/ca_certificate.crt`, but
the Python never emitted the key, so Puppet saw `undef` and the file was never
populated.

### File output

Without `--json` the certificate is written under `vault.output_path`
(defaulting to the working directory):

| Path | Contents |
|---|---|
| `<output_path>/<common_name>/certificate.crt` | Signed certificate |
| `<output_path>/<common_name>/private.key` | Private key (mode 0600) |
| `<output_path>/<common_name>/full_chain.crt` | Issuing CA + certificate |
| `<output_path>/<common_name>/ca_certificate.crt` | Issuing CA certificate |

With `-c` the same four files are written into
`<output_path>/<common_name>.zip`.

## Configuration

YAML, everything nested under `vault:`. The path is baked in at build time
(`make build CONFIG_PATH=...`) and overridable per-invocation with `--config`.

| Key | Required | Default | Notes |
|---|---|---|---|
| `addr` | yes | | e.g. `https://vault.example.com:8200` |
| `auth_method` | no | `approle` | `approle` or `kubernetes` |
| `mount_point` | yes | | e.g. `pki_int` |
| `role_name` | yes | | e.g. `my-role` |
| `role_id` | iff `approle` | | |
| `approle_path` | iff `approle` | | e.g. `approle` |
| `k8s_mount` | iff `kubernetes` | | e.g. `kubernetes` |
| `k8s_role` | iff `kubernetes` | | e.g. `my-certmanager-role` |
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
binary with the exact argv Puppet uses and asserts on the issued certificate.
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
