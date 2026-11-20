# certmanager

Issues X.509 certificates from a [Vault](https://www.vaultproject.io/) (or
OpenBao) PKI secrets engine and prints the PKI mount's CA chain. It is a single
static binary designed to be called from Puppet's `generate()` function during
catalog compilation, so a Puppet server can hand each node a certificate, key
and CA chain, but it works as a standalone CLI too.

It authenticates to Vault with AppRole or Kubernetes auth, calls
`POST /v1/<mount_point>/issue/<role_name>`, and either prints the result as
JSON or writes it to files.

## Install

Download a release from
[GitHub releases](https://github.com/IUCLabs/certmanager/releases):

- `certmanager-<version>-1.<arch>.rpm` installs `/usr/bin/certmanager`, a
  `/usr/local/bin/certmanager` symlink and bash/zsh/fish completions.
- `certmanager-<os>-<arch>` is the raw binary (linux/darwin, amd64/arm64).
- `certmanager_<version>_<os>_<arch>.tar.gz` holds the binary, README and
  completions.

Verify downloads against `checksums.txt`, which is signed with a detached GPG
signature (`checksums.txt.sig`):

```bash
gpg --verify checksums.txt.sig checksums.txt
sha256sum --check --ignore-missing checksums.txt
```

Or build from source (Go per `go.mod`):

```bash
git clone https://github.com/IUCLabs/certmanager.git
cd certmanager
make build    # -> dist/certmanager (CGO disabled, static)
make install  # go install into $GOPATH/bin
```

## Usage

```
certmanager <common_name> [flags]   # issue a certificate
certmanager ca [flags]              # print the CA chain
certmanager                         # print help (interactive terminals only)
```

```bash
certmanager host.example.com --alt-names "host,host.example.com" \
  --ip-sans "127.0.0.1,192.0.2.10" --expiry-days 90 --json
```

The common name is positional. `ca`, `completion` and `help` are the
subcommands; every other first argument is a common name.

A bare invocation prints help and exits zero only when stdout is a terminal. A
pipe, a file, `/dev/null` or a closed stdout exits non-zero with nothing on
stdout, so a call that lost its common name fails instead of emitting help
text.

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

On success nothing is written to stderr; every failure prints the cause to
stderr and exits non-zero.

### JSON output

```json
{
  "certificate": "<PEM leaf>",
  "private_key": "<PEM key>",
  "full_chain": "<certificate PEM>\n<issuing_ca PEM>"
}
```

`full_chain` is leaf first, the order TLS servers expect. The CA chain is not
part of this document; fetch it with `certmanager ca`.

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

### The `ca` subcommand

```
certmanager ca [--mount <pki_mount>] [--config <path>]
```

Prints the mount's CA chain to stdout as raw PEM, read unauthenticated from
`GET /v1/<mount>/ca_chain`. A config carrying only `addr` and `mount_point` is
enough, and `--mount` overrides the configured mount.

`/ca_chain` returns the intermediate **and** the root, unlike `issuing_ca` or
`/ca/pem`, so the output works as a standalone `CAfile` for path builders that
require a self-signed anchor. The response must be a PEM certificate chain; a
non-200, an empty body or anything else exits non-zero with nothing on stdout.

### Puppet

`generate()` merges the command's stderr into its stdout, so the contract above
means the JSON can go straight to `parsejson()` and a failure aborts the
compile with a readable error. A minimal example:

```puppet
$cert = parsejson(generate(
  '/usr/local/bin/certmanager', $facts['networking']['fqdn'],
  '--alt-names', "${facts['networking']['hostname']},${facts['networking']['fqdn']}",
  '--ip-sans', "127.0.0.1,${facts['networking']['ip']}",
  '--expiry-days', '90',
  '--json',
))

file { '/etc/pki/tls/vault/ca_certificate.crt':
  content => generate('/usr/local/bin/certmanager', 'ca'),
}
```

## Configuration

YAML, everything nested under `vault:`.

### Config resolution order

1. `--config <path>`, which always wins; an empty `--config ''` is an error;
2. `$XDG_CONFIG_HOME/certmanager/config.yaml`, if `$XDG_CONFIG_HOME` is
   absolute and the file exists;
3. `$HOME/.config/certmanager/config.yaml`, if the file exists;
4. `/opt/certmanager/config.yaml`, the path baked in at build time
   (`make build CONFIG_PATH=...`).

Steps 2 and 3 are skipped unless the file exists, so a service user without a
usable home directory (such as `puppet` under `generate()`) lands on the
built-in path.

| Key | Required | Default | Notes |
|---|---|---|---|
| `addr` | yes | | e.g. `https://vault.example.com:8200` |
| `auth_method` | no | `approle` | `approle` or `kubernetes` |
| `mount_point` | yes | | e.g. `pki_int` |
| `role_name` | iff issuing | | e.g. `my-role` |
| `role_id` | iff `approle` and issuing | | |
| `approle_path` | iff `approle` and issuing | | e.g. `approle` |
| `k8s_mount` | iff `kubernetes` and issuing | | e.g. `kubernetes` |
| `k8s_role` | iff `kubernetes` and issuing | | e.g. `my-role` |
| `jwt_path` | no | `/var/run/secrets/kubernetes.io/serviceaccount/token` | |
| `output_path` | no | `.` | Non-JSON output directory |
| `tls_skip_verify` | no | `true` | Set `false` when Vault's certificate is trusted by the host |
| `timeout` | no | `30s` | Per-request Vault timeout |

```yaml
vault:
  addr: https://vault.example.com:8200
  auth_method: approle
  approle_path: approle
  role_id: <role_id>
  mount_point: pki_int
  role_name: my-role
  output_path: /var/lib/certmanager
```

`ca` requires only `addr` and a mount; every auth key above is optional for it.

AppRole logs in with `role_id` only, so the Vault role must set
`bind_secret_id: false`. Kubernetes reads the JWT from `jwt_path` and posts it
with `k8s_role`. A missing, unreadable or empty JWT, a rejected login, or an
unknown `auth_method` each fail naming the cause; there is no fallback between
methods.

## Development

```sh
make build             # -> dist/certmanager (CGO disabled, static)
make test              # go test -v -race ./...
make lint              # golangci-lint
make pre-commit        # uvx pre-commit run --all-files
make completions       # -> dist/completions/
make integration-test  # end-to-end against a real Vault dev server
make release-snapshot  # goreleaser: binaries, tar.gz and RPM into dist/
```

`make integration-test` starts a `hashicorp/vault` dev container with
docker/podman, provisions a root and intermediate PKI mount and an AppRole
role, then runs the built binary and asserts on the issued certificate and CA
chain. Point it at an existing dev server with `CERTMANAGER_IT_VAULT_ADDR`
(`VAULT_ADDR` is deliberately ignored, because the test writes to the PKI
mount).

## Releases

Pushing a `v*` tag runs GitHub Actions, where GoReleaser publishes the raw
binaries, tarballs, the RPM and a signed `checksums.txt` to the GitHub release.
