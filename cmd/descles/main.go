// Command descles connects agent harnesses to a customer's Descles edge.
//
//	descles connect claude-code --edge https://descles.internal --key <agent key> [--scope user|project]
//	descles connect codex       --edge https://descles.internal --key <agent key> [--model gpt-5.1-codex]
//	descles connect openai      --edge https://descles.internal --key <agent key>   (Hermes, SDKs, other agents)
//	descles hook claude-code pre|post --edge <url> --key-file <path>              (installed by connect)
//	descles key [--file <path>]                                                   (Claude Code apiKeyHelper)
//	descles edge init [--dir descles-edge] [--mode standalone|hosted] [--yes]     (generate a VPC edge deployment)
//	descles edge up   [--dir descles-edge]                                        (start it with docker compose)
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/chiatzenw-cur/descles/pkg/connect"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "descles:", err)
		os.Exit(1)
	}
}

func usage() error {
	return errors.New(`usage:
  descles connect claude-code|codex|openai --edge URL [--key KEY] [flags]
  descles hook claude-code pre|post --edge URL [--key-file PATH]
  descles key [--file PATH]
  descles edge init [--dir DIR] [--mode standalone|hosted] [--yes]
  descles edge up [--dir DIR]`)
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "connect":
		if len(args) < 2 {
			return usage()
		}
		return runConnect(args[1], args[2:])
	case "hook":
		if len(args) < 3 || args[1] != "claude-code" {
			return usage()
		}
		return runHook(args[2], args[3:])
	case "edge":
		if len(args) < 2 {
			return usage()
		}
		switch args[1] {
		case "init":
			return runEdgeInit(args[2:])
		case "up":
			return runEdgeUp(args[2:])
		}
		return usage()
	case "key":
		fs := flag.NewFlagSet("key", flag.ContinueOnError)
		def, _ := connect.KeyFile()
		file := fs.String("file", def, "agent key file")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		key, err := connect.LoadKey(*file)
		if err != nil {
			return err
		}
		fmt.Println(key)
		return nil
	}
	return usage()
}

func runConnect(target string, args []string) error {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	edgeURL := fs.String("edge", os.Getenv("DESCLES_EDGE_URL"), "edge base URL")
	key := fs.String("key", os.Getenv("DESCLES_AGENT_KEY"), "agent virtual key (not a provider key)")
	scope := fs.String("scope", "user", "claude-code: user (~/.claude/settings.json) or project (.claude/settings.local.json)")
	model := fs.String("model", "", "codex: default model for the descles profile")
	dryRun := fs.Bool("dry-run", false, "print what would change without writing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	base, err := connect.NormalizeURL(*edgeURL)
	if err != nil {
		return err
	}
	keyFile, err := connect.KeyFile()
	if err != nil {
		return err
	}
	if *key == "" {
		if *key, err = connect.LoadKey(keyFile); err != nil {
			return errors.New("--key is required the first time (or set DESCLES_AGENT_KEY)")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	edge := connect.Edge{URL: base, Key: *key}
	connectors, err := edge.Connectors(ctx)
	if err != nil {
		return fmt.Errorf("cannot verify the edge and key: %w", err)
	}
	fmt.Printf("edge %s ok; connectors: %s\n", base, strings.Join(connectors, ", "))
	if !*dryRun {
		if err := connect.SaveKey(keyFile, *key); err != nil {
			return err
		}
	}

	switch target {
	case "claude-code":
		return connectClaude(base, *key, keyFile, *scope, connectors, *dryRun)
	case "codex":
		return connectCodex(base, *model, connectors, *dryRun)
	case "openai", "hermes":
		fmt.Print(connect.OpenAIInstructions(base, connectors))
		return nil
	}
	return fmt.Errorf("unknown target %q (claude-code, codex, openai)", target)
}

func connectClaude(base, key, keyFile, scope string, connectors []string, dryRun bool) error {
	var path, mcpScope string
	switch scope {
	case "user":
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		path, mcpScope = filepath.Join(home, ".claude", "settings.json"), "user"
	case "project":
		path, mcpScope = filepath.Join(".claude", "settings.local.json"), "local"
	default:
		return fmt.Errorf("--scope must be user or project")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	existing, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	updated, err := connect.ClaudeSettings(existing, base, self, keyFile)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	cmds := connect.ClaudeMCPCommands(base, key, connectors, mcpScope)
	if dryRun {
		fmt.Printf("--- %s ---\n%s", path, updated)
		for _, c := range cmds {
			fmt.Println(strings.Join(redact(c, key), " "))
		}
		return nil
	}
	if err := connect.WriteFileWithBackup(path, updated); err != nil {
		return err
	}
	fmt.Printf("wrote %s (previous version in .bak): model traffic -> %s/anthropic, native tools -> edge policy hooks\n", path, base)
	if _, err := exec.LookPath("claude"); err != nil {
		fmt.Println("claude CLI not on PATH; register MCP connectors with:")
		for _, c := range cmds {
			fmt.Println("  " + strings.Join(redact(c, key), " "))
		}
		return nil
	}
	for _, c := range cmds {
		// Re-running connect replaces the entry instead of failing on a duplicate.
		_ = exec.Command(c[0], "mcp", "remove", "--scope", mcpScope, c[7]).Run()
		if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("claude mcp add %s: %v: %s", c[7], err, strings.TrimSpace(string(out)))
		}
		fmt.Println("registered MCP server", c[7])
	}
	fmt.Println("restart Claude Code to pick up the changes")
	return nil
}

func redact(cmd []string, key string) []string {
	out := make([]string, len(cmd))
	for i, c := range cmd {
		out[i] = strings.ReplaceAll(c, key, "$DESCLES_AGENT_KEY")
		if strings.Contains(out[i], " ") {
			out[i] = "\"" + out[i] + "\""
		}
	}
	return out
}

func connectCodex(base, model string, connectors []string, dryRun bool) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	path := filepath.Join(home, ".codex", "config.toml")
	existing, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	updated := connect.CodexConfig(string(existing), base, model, connectors)
	if dryRun {
		fmt.Printf("--- %s ---\n%s", path, updated)
		return nil
	}
	if err := connect.WriteFileWithBackup(path, []byte(updated)); err != nil {
		return err
	}
	fmt.Printf("wrote %s (previous version in .bak)\n", path)
	fmt.Println("run:  export DESCLES_AGENT_KEY=\"$(descles key)\" && codex --profile descles")
	fmt.Println("note: Codex has no pre-execution hook, so its built-in shell is not checked by the edge.")
	fmt.Println("      Keep Codex's sandbox on, and expose sensitive systems only through edge MCP connectors.")
	return nil
}

func runHook(phase string, args []string) error {
	fs := flag.NewFlagSet("hook", flag.ContinueOnError)
	edgeURL := fs.String("edge", os.Getenv("DESCLES_EDGE_URL"), "edge base URL")
	def, _ := connect.KeyFile()
	keyFile := fs.String("key-file", def, "agent key file")
	failOpen := fs.Bool("fail-open", os.Getenv("DESCLES_HOOK_FAIL_OPEN") == "1", "allow tools when the edge is unreachable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	base, err := connect.NormalizeURL(*edgeURL)
	if err != nil {
		return err
	}
	key, err := connect.LoadKey(*keyFile)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res := connect.ClaudeHook(ctx, connect.Edge{URL: base, Key: key}, phase, os.Stdin, *failOpen)
	if res.Stdout != "" {
		fmt.Println(res.Stdout)
	}
	if res.Stderr != "" {
		fmt.Fprintln(os.Stderr, res.Stderr)
	}
	os.Exit(res.Code)
	return nil
}
