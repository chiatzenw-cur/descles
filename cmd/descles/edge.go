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
	fs.StringVar(&o.Mode, "mode", "", "standalone, selfhost (customer control plane), or legacy hosted")
	fs.StringVar(&o.EdgeID, "edge-id", "", "stable edge id")
	fs.StringVar(&providers, "providers", "", "comma list: anthropic,openai")
	fs.StringVar(&o.OpenAIBase, "openai-base", "", "OpenAI-compatible upstream base URL")
	fs.Var(&connectors, "connector", "MCP connector id=url (repeatable)")
	fs.StringVar(&o.AgentName, "agent", "", "standalone: id of the first agent")
	fs.StringVar(&o.HostedURL, "control-plane", "", "managed: control plane origin (https://...)")
	fs.StringVar(&o.OrgID, "org", "", "managed: organization id")
	fs.StringVar(&o.BundleKey, "bundle-key", "", "managed: control plane Ed25519 bundle key (hex), from a trusted channel")
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

// dockerEngineUp reports the engine version behind the current docker context, or
// false if the engine is not reachable (Docker Desktop stopped, pipe not created yet).
func dockerEngineUp() (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "info", "--format", "{{.ServerVersion}}").Output()
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(out)), true
}

// dockerDesktopExe finds the Docker Desktop launcher, if it is installed. Recent
// Docker Desktop releases install per-user under
// %LOCALAPPDATA%\Programs\DockerDesktop\frontend\, older ones under Program Files.
func dockerDesktopExe() string {
	if exe, err := exec.LookPath("Docker Desktop.exe"); err == nil {
		return exe
	}
	local, pf, pf86 := os.Getenv("LOCALAPPDATA"), os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)")
	candidates := []string{
		filepath.Join(local, "Programs", "DockerDesktop", "frontend", "Docker Desktop.exe"),
		filepath.Join(local, "Programs", "DockerDesktop", "Docker Desktop.exe"),
		filepath.Join(local, "Programs", "Docker", "Docker", "Docker Desktop.exe"),
		filepath.Join(local, "Docker", "Docker Desktop.exe"),
		filepath.Join(pf, "Docker", "Docker", "Docker Desktop.exe"),
		filepath.Join(pf86, "Docker", "Docker", "Docker Desktop.exe"),
		"/Applications/Docker.app",
	}
	patterns := []string{
		filepath.Join(local, "Programs", "DockerDesktop", "*", "Docker Desktop.exe"),
		filepath.Join(local, "Programs", "DockerDesktop", "app", "*", "Docker Desktop.exe"),
	}
	for _, p := range patterns {
		if p == "" {
			continue
		}
		if m, _ := filepath.Glob(p); len(m) > 0 {
			return m[0]
		}
	}
	for _, p := range candidates {
		if p == "" {
			continue
		}
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

// dockerDesktopLaunch returns the command that starts Docker Desktop, if it is
// installed (macOS needs `open -a Docker`; the .app bundle is a directory).
func dockerDesktopLaunch() (*exec.Cmd, bool) {
	if exe := dockerDesktopExe(); exe != "" {
		return exec.Command(exe), true
	}
	if st, err := os.Stat("/Applications/Docker.app"); err == nil && st.IsDir() {
		return exec.Command("open", "-a", "Docker"), true
	}
	return nil, false
}

// dockerContextName returns the active docker context.
func dockerContextName() string {
	out, err := exec.Command("docker", "context", "show").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

func dockerEndpoint() string {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "context", "inspect", "-f",
		"{{.Endpoints.docker.Host}}").Output()
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

// ensureDockerEngine removes the most common way `edge up` fails: Docker Desktop is
// installed and the compose file is fine, but the engine (the named pipe the docker
// CLI talks to) is not up yet - typically right after a reboot or a desktop restart.
// Rather than surfacing a bare `docker compose up: exit status 1`, start Docker
// Desktop, wait for the engine, and if it never appears, say what is actually wrong.
func ensureDockerEngine(wait time.Duration) error {
	if v, ok := dockerEngineUp(); ok {
		_ = v
		return nil
	}
	desktop, haveDesktop := dockerDesktopLaunch()
	// An explicit DOCKER_HOST pointing somewhere is a configuration choice, not a
	// startup race: never override it by launching Docker Desktop.
	if haveDesktop && os.Getenv("DOCKER_HOST") == "" {
		fmt.Printf("docker engine not reachable; starting Docker Desktop (waiting up to %s)\n", wait.Round(time.Second))
		desktop.Stdout, desktop.Stderr = nil, nil
		if err := desktop.Start(); err == nil {
			_ = desktop.Process.Release() // the launcher stays resident; do not wait on it
			deadline := time.Now().Add(wait)
			for time.Now().Before(deadline) {
				time.Sleep(2 * time.Second)
				if v, ok := dockerEngineUp(); ok {
					fmt.Printf("docker engine %s is up\n", v)
					return nil
				}
			}
		}
	}
	hint := "start Docker Desktop and re-run"
	switch {
	case os.Getenv("DOCKER_HOST") != "":
		hint = fmt.Sprintf("DOCKER_HOST is set to %s; fix it or unset it and re-run", os.Getenv("DOCKER_HOST"))
	case !haveDesktop:
		hint = "install Docker Desktop, or point DOCKER_HOST at a reachable engine"
	}
	return fmt.Errorf("docker engine is not reachable\n"+
		"  context:  %s\n  endpoint: %s\n  fix:      %s\n  check:    docker info",
		dockerContextName(), dockerEndpoint(), hint)
}

func runEdgeUp(args []string) error {
	fs := flag.NewFlagSet("edge up", flag.ContinueOnError)
	dir := fs.String("dir", "descles-edge", "deployment directory from `descles edge init`")
	wait := fs.Duration("wait", 90*time.Second, "how long to wait for the Docker engine to start")
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
	if err := ensureDockerEngine(*wait); err != nil {
		return err
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
				if envRaw, readErr := os.ReadFile(filepath.Join(*dir, "edge.env")); readErr == nil && strings.Contains(string(envRaw), "DESCLES_EDGE_REPORT_URL=off") && strings.Contains(string(envRaw), "DESCLES_EDGE_BUNDLE_URL=") {
					fmt.Printf("Team workspace: http://127.0.0.1:%d/ (customer control-plane token)\n", port)
				}
				fmt.Printf("local edge console: http://127.0.0.1:%d/admin/ (admin token: %s)\n", port, filepath.Join(*dir, "config", "secrets", "admin-token"))
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
	o.Mode = ask("Mode: standalone, selfhost (customer control plane), or legacy hosted", nonEmpty(o.Mode, "standalone"))
	o.EdgeID = ask("Edge id", nonEmpty(o.EdgeID, "edge-1"))
	if len(o.Providers) == 0 {
		o.Providers = splitList(ask("Model providers (anthropic,openai)", "anthropic,openai"))
	}
	if o.Mode == "hosted" || o.Mode == "selfhost" {
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
