path "secret-v2/data/shared-secret/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "secret-v2/metadata/shared-secret/*" {
  capabilities = ["list"]
}
#for mcp access
path "sys/mounts" {
  capabilities = ["read"]
}