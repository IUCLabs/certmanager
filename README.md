# certmanager

Vault PKI certificate issuance and SSH host key signing tool for Puppet-managed infrastructure.

Replaces the Python `certmanager` and `sshsignhost` scripts deployed by Puppet, compiled to a single static binary with no runtime dependencies.

## Installation

```sh
make build          # produces ./certmanager
make install        # installs to $GOPATH/bin
```

## Configuration

Config file is read from `$XDG_CONFIG_HOME/certmanager/config.yaml` (defaults to `~/.config/certmanager/config.yaml`). Override with `--config`.

On Puppet-managed nodes the config is written to `/opt/certmanager/config.yaml` by `profiles::helpers::certmanager`.

### Auth methods

#### AppRole (current — Puppet nodes)

```yaml
vault:
  addr: https://vault.example.com:8200
  auth_method: approle
  approle_path: approle      # optional, defaults to "approle"
  role_id: <role_id>
  secret_id: <secret_id>     # optional
  mount_point: pki_int
  role_name: my-role
  output_path: /tmp/certmanager
```

#### LDAP (testing / interactive use)

```yaml
vault:
  addr: https://vault.example.com:8200
  auth_method: ldap
  ldap_path: ldap            # optional, defaults to "ldap"
  ldap_username: alice
  ldap_password: secret
  mount_point: pki_int
  role_name: my-role
  output_path: /tmp/certmanager
```

#### Kubernetes (Puppet running in-cluster)

```yaml
vault:
  addr: https://vault.example.com:8200
  auth_method: kubernetes
  kubernetes_path: kubernetes   # optional, defaults to "kubernetes"
  kubernetes_role: puppet
  kubernetes_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token  # optional
  mount_point: pki_int
  role_name: my-role
  output_path: /tmp/certmanager
```

#### Token (bootstrap / testing)

```yaml
vault:
  addr: https://vault.example.com:8200
  auth_method: token
  token: hvs.XXXX
  mount_point: pki_int
  role_name: my-role
  output_path: /tmp/certmanager
```

> **Note:** `auth_method` defaults to `approle` when omitted, preserving backwards compatibility with the existing Python script config format.

## Usage

### PKI certificate

```sh
# Write files to output_path/<common_name>/
certmanager pki host.example.com \
  --alt-names host,host.example.com \
  --ip-sans 127.0.0.1,192.0.2.1 \
  --expiry-days 90

# JSON output (for use with Puppet generate())
certmanager pki host.example.com \
  --alt-names host,host.example.com \
  --ip-sans 127.0.0.1,192.0.2.1 \
  --expiry-days 90 \
  --json
```

Output files (written to `<output_path>/<common_name>/`):

| File | Contents |
|---|---|
| `certificate.crt` | Signed certificate |
| `private.key` | Private key (mode 0600) |
| `ca_certificate.crt` | Issuing CA certificate |
| `full_chain.crt` | CA + certificate |
| `certificate.pem` | Certificate + key bundle (mode 0600) |

JSON keys: `certificate`, `private_key`, `ca_certificate`, `full_chain`.

### SSH host certificate signing

```sh
# Plain output (signed cert to stdout)
certmanager ssh \
  --public-key "ssh-rsa AAAA..." \
  --valid-principals host.example.com,host,192.0.2.1

# JSON output (for use with Puppet generate())
certmanager ssh \
  --public-key "$(cat /etc/ssh/ssh_host_rsa_key.pub)" \
  --valid-principals host.example.com,host \
  --ttl 87600h \
  --json
```

JSON key: `signed_key`.

### Global flags

| Flag | Default | Description |
|---|---|---|
| `--config` | `~/.config/certmanager/config.yaml` | Path to config file |

## Development

```sh
make build        # compile
make test         # run tests
make test-verbose # run tests with -v
make tidy         # go mod tidy
make lint         # golangci-lint (requires golangci-lint installed)
```

## Release

Uses [goreleaser](https://goreleaser.com/). Tag a version and run:

```sh
goreleaser release --clean
```
