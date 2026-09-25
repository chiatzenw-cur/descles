package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/chiatzenw-cur/descles/pkg/edgeinit"
)

type connectorFlags []edgeinit.Connector

func (c *connectorFlags) String() string { return fmt.Sprint(*c) }
func (c *connectorFlags) Set(v string) error {
	id, u, ok := strings.Cut(v, "=")
	if !ok {
		return errors.New("use id=url")
	}
	*c = append(*c, edgeinit.Connector{ID: strings.TrimSpace(id), URL: strings.TrimSpace(u)})
	return nil
}

func runEdgeInit(args []string) error {
	fs := flag.NewFlagSet("edge init", flag.ContinueOnError)
	o := edgeinit.Options{UID: os.Getuid(), GID: os.Getgid()}
	var providers string
	var connectors connectorFlags
	fs.StringVar(&o.Dir, "dir", "descles-edge", "output directory")
	fs.StringVar(&o.Mode, "mode", "", "standalone (no hosted control plane) or hosted")
	fs.StringVar(&o.EdgeID, "edge-id", "", "stable edge id")
	fs.StringVar(&providers, "providers", "", "comma list: anthropic,openai")
	fs.StringVar(&o.OpenAIBase, "openai-base", "", "OpenAI-compatible upstream base URL")
	fs.Var(&connectors, "connector", "MCP connector id=url (repeatable)")
	fs.StringVar(&o.AgentName, "agent", "", "standalone: id of the first agent")
	fs.StringVar(&o.HostedURL, "control-plane", "", "hosted: control plane origin (https://...)")
	fs.StringVar(&o.OrgID, "org", "", "hosted: organization id")
	fs.StringVar(&o.BundleKey, "bundle-key", "", "hosted: control plane Ed25519 bundle key (hex), from a trusted channel")
	fs.StringVar(&o.Image, "image", "", "edge container image (default "+edgeinit.DefaultImage+")")
	fs.IntVar(&o.Port, "port", 0, "loopback port for the edge (default 8081)")
	fs.BoolVar(&o.OrgContext, "org-context", false, "add organization-context config (requires the enterprise edge image)")
	yes := fs.Bool("yes", false, "no prompts; use flags and defaults")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if providers != "" {
		o.Providers = splitList(providers)
	}
	o.Connectors = connectors
	if !*yes && isTerminal() {
		if err := prompt(&o); err != nil {
			return err
		}
	}
	res, err := edgeinit.Generate(o)
	if err != nil {
		return err
	}
	fmt.Printf("created %s:\n", o.Dir)
	for _, f := range res.Files {
		fmt.Println("  " + f)
	}
	if res.AgentKey != "" {
		fmt.Printf("\nagent key for %q (shown once; only its hash is stored):\n  %s\n", nonEmpty(o.AgentName, "agent-1"), res.AgentKey)
	}
	fmt.Println("\nnext:")
	for i, n := range res.Next {
		fmt.Printf("  %d. %s\n", i+1, n)
	}
	return nil
}

func runEdgeUp(args []string) error {
	fs := flag.NewFlagSet("edge up", flag.ContinueOnError)
	dir := fs.String("dir", "descles-edge", "deployment directory from `descles edge init`")
	if err := fs.Parse(args); err != nil {
		return err
	}
	compose := filepath.Join(*dir, "compose.yml")
	raw, err := os.ReadFile(compose)
	if err != nil {
		return fmt.Errorf("no deployment in %s (run `descles edge init` first): %w", *dir, err)
	}
	if err := secretsFilled(*dir); err != nil {
		return err
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return errors.New("docker not found; deploy compose.yml with your own tooling")
	}
	cmd := exec.Command("docker", "compose", "-f", compose, "up", "-d")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker compose up: %w", err)
	}
	port := 8081
	if m := regexp.MustCompile(`127\.0\.0\.1:(\d+):8080`).FindSubmatch(raw); m != nil {
		port, _ = strconv.Atoi(string(m[1]))
	}
	health := fmt.Sprintf("http://127.0.0.1:%d/healthz", port)
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, health, nil)
		resp, err := http.DefaultClient.Do(req)
		cancel()
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				fmt.Printf("edge healthy at http://127.0.0.1:%d\n", port)
				fmt.Printf("connect an agent: descles connect claude-code --edge http://127.0.0.1:%d --key <agent key>\n", port)
				return nil
			}
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("edge did not become healthy; check: docker compose -f %s logs", compose)
}

// secretsFilled refuses to start with empty credential placeholders, which
// would only produce a confusing container crash loop.
func secretsFilled(dir string) error {
	entries, err := os.ReadDir(filepath.Join(dir, "config", "secrets"))
	if err != nil {
		return nil
	}
	var empty []string
	for _, e := range entries {
		if info, err := e.Info(); err == nil && !e.IsDir() && info.Size() == 0 {
			empty = append(empty, filepath.ToSlash(filepath.Join("config", "secrets", e.Name())))
		}
	}
	if len(empty) > 0 {
		return fmt.Errorf("fill these credential files first (they stay on this machine): %s", strings.Join(empty, ", "))
	}
	return nil
}

func isTerminal() bool {
	info, err := os.Stdin.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func prompt(o *edgeinit.Options) error {
	in := bufio.NewReader(os.Stdin)
	ask := func(q, def string) string {
		if def != "" {
			fmt.Printf("%s [%s]: ", q, def)
		} else {
			fmt.Printf("%s: ", q)
		}
		line, _ := in.ReadString('\n')
		if line = strings.TrimSpace(line); line == "" {
			return def
		}
		return line
	}
	o.Mode = ask("Mode: standalone (no Descles cloud) or hosted", nonEmpty(o.Mode, "standalone"))
	o.EdgeID = ask("Edge id", nonEmpty(o.EdgeID, "edge-1"))
	if len(o.Providers) == 0 {
		o.Providers = splitList(ask("Model providers (anthropic,openai)", "anthropic,openai"))
	}
	if o.Mode == "hosted" {
		o.HostedURL = ask("Control plane origin", o.HostedURL)
		o.OrgID = ask("Organization id", o.OrgID)
		o.BundleKey = ask("Bundle public key (hex, from your console over a trusted channel)", o.BundleKey)
	} else {
		o.AgentName = ask("First agent id", nonEmpty(o.AgentName, "agent-1"))
	}
	if len(o.Connectors) == 0 {
		fmt.Println("MCP connectors as id=url, empty line to finish:")
		for {
			line := ask("  connector", "")
			if line == "" {
				break
			}
			var c connectorFlags
			if err := c.Set(line); err != nil {
				fmt.Println("  ", err)
				continue
			}
			o.Connectors = append(o.Connectors, c...)
		}
	}
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func nonEmpty(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
