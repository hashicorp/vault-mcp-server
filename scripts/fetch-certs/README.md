# fetch-secrets (certs-puller)
This helper downloads a private CA bundle into a file (typically a shared Docker volume) so `vault-mcp-server` can trust an upstream Vault endpoint that uses a private PKI.

It is designed to run as a one-shot container in Compose (service name usually `certs-puller`).

## Behavior
- If the destination file exists and is non-empty, it exits `0` (no-op).
- If the destination file is missing/empty, it downloads the bundle from the URL, validates it contains PEM certificates, writes atomically, then exits `0`.

## Configuration
Environment variables (preferred):
- `ENTERPRISE_IO_CACERT_FILE`: destination file path to write the PEM bundle to
- `ENTERPRISE_IO_CACERT_URL`: URL to download the PEM bundle from

Backward-compatibility (older compose files):
- `VIASAT_IO_CACERT_FILE`
- `VIASAT_IO_CACERT_URL`

Flags (override env vars):
- `--file <path>`
- `--url <url>`
- `--timeout <duration>` (default: `30s`)
- `--force` (re-fetch even if the destination file already exists)

## Using the enterprise Compose template
The repository includes `docker-compose-ENTERPRISE_EXAMPLE.yaml` as a template you can copy and fill in.

1) Copy the template:
```sh
cp docker-compose-ENTERPRISE_EXAMPLE.yaml docker-compose-enterprise.yaml
```

2) Edit `docker-compose-enterprise.yaml`:
- Set `VAULT_ADDR` to your upstream Vault URL.
- Set `ENTERPRISE_IO_CACERT_URL` to where your private CA bundle is hosted.
- Ensure the file written by `certs-puller` matches what `vault-mcp-server` uses:
  - `ENTERPRISE_IO_CACERT_FILE` (certs-puller writes here)
  - `VAULT_CACERT` (vault-mcp-server reads from here)
- Update the `vault-mcp-server` image/registry as needed for your environment.

3) Run it:
```sh
docker compose -f docker-compose-enterprise.yaml up --build

docker compose -f docker-compose-company.yaml up 
[+] up 1/1
 ✔ Container vault-mcp-server-certs-puller-1 Recreated                                                                                                                                                        0.0s
Attaching to certs-puller-1, vault-mcp-server-1
Container vault-mcp-server-certs-puller-1 Waiting 
certs-puller-1  | private ca root fetched: /enterprise/certs/company.io.pem (42728 bytes)
certs-puller-1 exited with code 0
Container vault-mcp-server-certs-puller-1 Exited 
vault-mcp-server-1  | {"level":"info","msg":"private ca root ready","path":"/enterprise/certs/company.io.pem","size_bytes":42728,"time":"2026-07-02T21:30:53.441396922Z"}
vault-mcp-server-1  | {"addr":"0.0.0.0:8250","cors_mode":"development","endpoint":"/mcp","level":"info","msg":"http server starting","time":"2026-07-02T21:30:53.446006964Z","tls":"disabled (not recommended for production)"}
vault-mcp-server-1  | {"cacert_file":"/enterprise/certs/company.io.pem","level":"info","msg":"vault connection","time":"2026-07-02T21:30:53.446043797Z","vault_addr":"https://vault.seceng-iam.company.io","vault_namespace":""}
vault-mcp-server-1  | {"access_token_ttl":"12h0m0s","ldap_mount":"ldap","level":"info","login_methods":"ldap, userpass, oidc","login_page":"http://0.0.0.0:8250/vault/login","msg":"oauth enabled","oidc_callback":"http://0.0.0.0:8250/oidc/callback","oidc_mount":"oidc","oidc_role":"","time":"2026-07-02T21:30:53.446242214Z","userpass_mount":"userpass"}
Gracefully Stopping... press Ctrl+C again to force
Container vault-mcp-server-vault-mcp-server-1 Stopping 
vault-mcp-server-1  | {"level":"info","msg":"Shutting down StreamableHTTP server...","time":"2026-07-02T21:30:56.562125382Z"}
Container vault-mcp-server-vault-mcp-server-1 Stopped 
Container vault-mcp-server-certs-puller-1 Stopping 
Container vault-mcp-server-certs-puller-1 Stopped 
vault-mcp-server-1 exited with code 0
```

## Example logs
Your output will vary, but a successful run typically looks like:

```text
certs-puller-1      | private ca root fetched: /enterprise/certs/enterprise.io.pem (42728 bytes)
vault-mcp-server-1  | {"level":"info","msg":"private ca root ready","path":"/enterprise/certs/enterprise.io.pem","size_bytes":42728,"time":"..."}
vault-mcp-server-1  | {"level":"info","msg":"http server starting","addr":"0.0.0.0:8250","time":"..."}
```

Note: `vault-mcp-server` will fail fast if a CA bundle path is configured (e.g. `VAULT_CACERT`) but the file does not exist at startup. The Compose pattern in the template uses `depends_on: condition: service_completed_successfully` to ensure certs are present before the server starts.
