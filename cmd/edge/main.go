// Command descles-edge is the open-core Descles edge: the data plane that runs
// in the customer's network, holds provider and tool credentials, enforces
// policy, and records locally. It contains no hosted control-plane code
// (enforced by pkg/edgeapp/boundary_test.go) and no extensions.
//
// Configuration is the DESCLES_* environment; `descles edge init` generates a
// working set.
package main

import (
	"os"

	"github.com/chiatzenw-cur/descles/pkg/edgeapp"
)

func main() { os.Exit(edgeapp.Main()) }
