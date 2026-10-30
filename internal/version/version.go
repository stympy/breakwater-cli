// Package version holds the build version, set with -ldflags at release time.
package version

// Version is overridden at build time with
// -X github.com/stympy/breakwater-cli/internal/version.Version=...
var Version = "dev"

// UserAgent is sent on every HTTP request the CLI makes.
func UserAgent() string {
	return "breakwater-cli/" + Version
}
