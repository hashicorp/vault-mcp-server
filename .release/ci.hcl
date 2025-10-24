# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

schema = "2"

project "vault-mcp-server" {
  team = "team-proj-mcp-servers"

  # slack channel : feed-vault-mcp-server-releases
  slack {
    notification_channel = "C09L03WD5R8"
  }

  github {
    organization     = "hashicorp"
    repository       = "vault-mcp-server"
    release_branches = ["main", "release/**"]
  }
}

event "merge" {
}

event "build" {
  action "build" {
    organization = "hashicorp"
    repository   = "vault-mcp-server"
    workflow     = "build"
    depends      = null
    config       = ""
  }

  depends = ["merge"]
}

event "prepare" {
  action "prepare" {
    organization = "hashicorp"
    repository   = "crt-workflows-common"
    workflow     = "prepare"
    depends      = ["build"]
    config       = ""
  }

  depends = ["build"]

  notification {
    on = "always"
  }
}

event "trigger-staging" {
}

event "promote-staging" {
  action "promote-staging" {
    organization = "hashicorp"
    repository   = "crt-workflows-common"
    workflow     = "promote-staging"
    depends      = null
    config       = "oss-release-metadata.hcl"
  }

  depends = ["trigger-staging"]

  notification {
    on = "always"
  }

}

event "trigger-production" {
}

event "promote-production" {
  action "promote-production" {
    organization = "hashicorp"
    repository   = "crt-workflows-common"
    workflow     = "promote-production"
    depends      = null
    config       = ""
  }

  depends = ["trigger-production"]

  notification {
    on = "always"
  }

}
