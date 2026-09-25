package edgeapp

import (
	"os/exec"
	"strings"
	"testing"
)

// The open-core edge must build from this repository alone: no dependency on
// any hosted Descles code may creep in.
func TestNoHostedDependencies(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not on PATH")
	}
	out, err := exec.Command("go", "list", "-deps", "../../...").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	for _, dep := range strings.Fields(string(out)) {
		if strings.Contains(dep, "descles-control-panel") || strings.HasSuffix(dep, "/controlplane") {
			t.Errorf("hosted dependency: %s", dep)
		}
	}
}
