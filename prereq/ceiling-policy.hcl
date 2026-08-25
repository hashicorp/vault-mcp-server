# Allow KV2 read and write
path "secret-v2/data/shared-secret/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "secret-v2/metadata/shared-secret/*" {
  capabilities = ["list"]
}
# Allow PKI operations
path "pki/issue/example-dot-com" {
  capabilities = ["create", "update"]
}
path "pki/cert/*" {
  capabilities = ["read"]
}
path "pki/certs" {
  capabilities = ["list"]
}
# Allow transit engine operations
path "transit/encrypt/app-key" {
  capabilities = ["update", "create", "read"]
}
# Allow decrypt
path "transit/decrypt/app-key" {
  capabilities = ["update", "create", "read"]
}
# Optional: allow key metadata read (safe)
path "transit/keys/app-key" {
  capabilities = ["read"]
}

#for mcp access
path "sys/mounts" {
  capabilities = ["read"]
}