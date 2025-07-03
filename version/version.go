// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package version

import (
	"fmt"
	"strings"
)

var (
	// Version is the main version number that is being run at the moment.
	Version = "0.1.0"

	// VersionPrerelease is a pre-release marker for the version. If this is ""
	// (empty string) then it means that it is a final release. Otherwise, this
	// is a pre-release such as "dev" (in development), "beta", "rc1", etc.
	VersionPrerelease = "dev"

	// GitCommit is the git commit that was compiled. This will be filled in by the compiler.
	GitCommit string

	// BuildDate is the date the binary was built
	BuildDate string
)

// GetHumanVersion composes the parts of the version in a way that's suitable
// for displaying to humans.
func GetHumanVersion() string {
	version := Version
	if VersionPrerelease != "" {
		version += fmt.Sprintf("-%s", VersionPrerelease)
	}

	return version
}

// SemVer is an instance of version.Version. This has the secondary
// benefit of verifying during tests and init time that our version is a
// proper semantic version, which should always be the case.
var SemVer = func() string {
	v := GetHumanVersion()
	if GitCommit != "" {
		v += fmt.Sprintf("+%s", GitCommit)
	}
	return v
}()

// Header is the header name used to send the current version
// in http requests.
const Header = "Vault-MCP-Server-Version"

// String returns the complete version string, including prerelease
func String() string {
	if VersionPrerelease != "" {
		return fmt.Sprintf("%s-%s", Version, VersionPrerelease)
	}
	return Version
}

// VersionNumber returns just the version number
func VersionNumber() string {
	return strings.Split(Version, "-")[0]
}
