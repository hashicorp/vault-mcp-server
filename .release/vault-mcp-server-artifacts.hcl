schema = 1
artifacts {
  zip = [
    "vault-mcp-server_${version}_darwin_amd64.zip",
    "vault-mcp-server_${version}_darwin_arm64.zip",
    "vault-mcp-server_${version}_freebsd_386.zip",
    "vault-mcp-server_${version}_freebsd_amd64.zip",
    "vault-mcp-server_${version}_linux_386.zip",
    "vault-mcp-server_${version}_linux_amd64.zip",
    "vault-mcp-server_${version}_linux_arm.zip",
    "vault-mcp-server_${version}_linux_arm64.zip",
    "vault-mcp-server_${version}_solaris_amd64.zip",
    "vault-mcp-server_${version}_windows_386.zip",
    "vault-mcp-server_${version}_windows_amd64.zip",
  ]
  container = [
    "vault-mcp-server_release-default_linux_386_${version}_${commit_sha}.docker.tar",
    "vault-mcp-server_release-default_linux_amd64_${version}_${commit_sha}.docker.tar",
    "vault-mcp-server_release-default_linux_arm64_${version}_${commit_sha}.docker.tar",
    "vault-mcp-server_release-default_linux_arm_${version}_${commit_sha}.docker.tar",
  ]
}
