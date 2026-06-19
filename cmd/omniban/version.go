// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

package main

import "runtime/debug"

// version is overridable at build time:
//
//	go build -ldflags "-X main.version=v1.0.0"
//
// It must stay initialized to a constant string for -X to take effect. When not
// stamped (e.g. `go install …@v1.0.0`), init() fills it from the module version
// the Go toolchain embeds from the VCS tag.
var version = ""

func init() {
	if version != "" {
		return
	}
	version = "dev"
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		version = bi.Main.Version
	}
}
