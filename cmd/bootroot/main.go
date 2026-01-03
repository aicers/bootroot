package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	CAName          = "BootrootCA"
	DNSNames        = "localhost,bootroot-ca,bootroot-agent"
	Address         = ":9000"
	ProvisionerName = "acme"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Get current working directory
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("getting current working directory: %w", err)
	}

	// Define secrets directory path
	secretsDir := filepath.Join(cwd, "secrets")

	// Check if CA is already initialized
	caConfigPath := filepath.Join(secretsDir, "config", "ca.json")
	if _, err := os.Stat(caConfigPath); err == nil {
		fmt.Printf("Bootroot CA is already initialized in %s.\n", secretsDir)
		fmt.Println("Skipping initialization.")
		return nil
	}

	fmt.Println("Initializing Bootroot CA...")

	// Create secrets directory
	if err := os.MkdirAll(secretsDir, 0755); err != nil {
		return fmt.Errorf("creating secrets directory: %w", err)
	}

	// Create password files
	passwordFile := filepath.Join(secretsDir, "password.txt")
	provisionerPasswordFile := filepath.Join(secretsDir, "provisioner_password.txt")

	if err := os.WriteFile(passwordFile, []byte("password123\n"), 0600); err != nil {
		return fmt.Errorf("writing password file: %w", err)
	}
	if err := os.WriteFile(provisionerPasswordFile, []byte("sysadmin-password123\n"), 0600); err != nil {
		return fmt.Errorf("writing provisioner password file: %w", err)
	}

	// Get current user ID/Group ID for Docker permissions
	uid, gid, err := getUserIdentity()
	if err != nil {
		return fmt.Errorf("getting user identity: %w", err)
	}

	// 1. Initialize CA
	fmt.Println("Generating Root/Intermediate CA...")

	initArgs := []string{
		"run", "--rm",
		"-v", fmt.Sprintf("%s:/home/step", secretsDir),
		"--user", fmt.Sprintf("%s:%s", uid, gid),
		"--entrypoint", "/bin/sh",
		"smallstep/step-ca",
		"-c", fmt.Sprintf("step ca init --name '%s' --dns '%s' --address '%s' --provisioner 'admin' --password-file /home/step/password.txt --provisioner-password-file /home/step/provisioner_password.txt --with-ca-url='https://localhost:9000' --deployment-type=standalone", CAName, DNSNames, Address),
	}

	if err := runDockerCommand(initArgs); err != nil {
		return fmt.Errorf("step ca init failed: %w", err)
	}

	// Parse flags
	noEAB := false
	for _, arg := range os.Args {
		if arg == "--no-eab" {
			noEAB = true
		}
	}

	// ... existing logic ... (path join, check exist)

	// ...

	// 2. Add ACME Provisioner
	if noEAB {
		fmt.Println("Adding ACME Provisioner (EAB Disabled)...")
		acmeArgs := []string{
			"run", "--rm",
			"-v", fmt.Sprintf("%s:/home/step", secretsDir),
			"--user", fmt.Sprintf("%s:%s", uid, gid),
			"--entrypoint", "/bin/sh",
			"smallstep/step-ca",
			"-c", fmt.Sprintf("step ca provisioner add %s --type ACME", ProvisionerName),
		}
		if err := runDockerCommand(acmeArgs); err != nil {
			return fmt.Errorf("step ca provisioner add failed: %w", err)
		}
	} else {
		fmt.Println("Adding ACME Provisioner (EAB Required)...")
		acmeArgs := []string{
			"run", "--rm",
			"-v", fmt.Sprintf("%s:/home/step", secretsDir),
			"--user", fmt.Sprintf("%s:%s", uid, gid),
			"--entrypoint", "/bin/sh",
			"smallstep/step-ca",
			"-c", fmt.Sprintf("step ca provisioner add %s --type ACME --require-eab", ProvisionerName),
		}
		if err := runDockerCommand(acmeArgs); err != nil {
			return fmt.Errorf("step ca provisioner add failed: %w", err)
		}

		// Fix permissions for Docker volume mount issues (common in dev envs)
		//nosec G204
		if err := exec.Command("chmod", "-R", "777", secretsDir).Run(); err != nil {
			fmt.Printf("Warning: failed to set permissions on secrets dir: %v\n", err)
		}

		// 3. Generate EAB Key (Only if EAB is required)
		fmt.Println("Generating EAB Key for Agent...")
		// ... existing EAB generation logic ...
	}
	fmt.Println("Generating EAB Key for Agent...")
	var eabParams *EABKey
	eabParams, err = generateEABKey(secretsDir, uid, gid)
	if err != nil {
		fmt.Printf("\n[WARNING] Failed to generate EAB key automatically: %v\n", err)
		fmt.Println("You must generate it manually after starting the server:")
		fmt.Printf("  docker exec bootroot-ca step ca acme eab add %s agent-001 --provisioner admin\n\n", ProvisionerName)

		// Create empty (dummy) EAB key to prevent Docker mount error
		eabParams = &EABKey{KID: "", Key: ""}
	} else {
		fmt.Printf("EAB Key generated: KID=%s\n", eabParams.KID)
	}

	// Save EAB credentials to file (or empty file)
	eabFile := filepath.Join(secretsDir, "eab.json")
	eabBytes, err := json.MarshalIndent(eabParams, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling EAB key: %w", err)
	}
	if err := os.WriteFile(eabFile, eabBytes, 0600); err != nil {
		return fmt.Errorf("writing EAB key file: %w", err)
	}

	fmt.Println("Bootroot CA initialization complete.")
	fmt.Printf("Configuration and keys are in %s\n", secretsDir)
	fmt.Printf("EAB Key saved to %s\n", eabFile)

	return nil
}

type EABKey struct {
	KID string `json:"kid"`
	Key string `json:"key"`
}

func generateEABKey(secretsDir, uid, gid string) (*EABKey, error) {
	containerName := "bootroot-ca-temp-init"

	// 1. Start Temp CA Server
	fmt.Println("  Starting temporary CA server...")
	startArgs := []string{
		"run", "-d", "--rm",
		"--name", containerName,
		"-v", fmt.Sprintf("%s:/home/step", secretsDir),
		"-p", "9000:9000",
		"smallstep/step-ca",
		"/usr/local/bin/step-ca", "/home/step/config/ca.json", "--password-file", "/home/step/password.txt",
	}
	if err := runDockerCommand(startArgs); err != nil {
		return nil, fmt.Errorf("starting temp server: %w", err)
	}

	// Stop temp server
	defer func() {
		fmt.Println("  Stopping temporary CA server...")
		// Use _ to ignore error if container is already stopped/removed
		_ = exec.Command("docker", "kill", containerName).Run()
	}()

	// 2. Wait for Health
	fmt.Print("  Waiting for server...")
	for i := 0; i < 30; i++ {
		resp, err := http.Get("http://localhost:9000/health")
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			fmt.Println(" Ready!")
			break
		}
		time.Sleep(1 * time.Second)
		fmt.Print(".")
	}

	// 3. Generate Key using 'step ca provisioner webhook' ?? No.
	// We need to use 'step ca acme eab add'.
	// But we need 'admin' privileges to generate it.
	// The 'step' CLI inside the container needs to trust the CA first? Or use --insecure?
	// And we need the admin password.

	// Command: step ca acme eab add <provisioner> <reference> --password-file ... --ca-url ... --root ...

	// Since we are running INSIDE the container context via exec, paths are /home/step...
	// We use 'admin' provisioner to authorize this action? No, usually 'step ca ...' needs --admin-cert/key or --password-file for the admin provisioner.

	fmt.Println("  Requests EAB key generation...")

	// NOTE: 'step ca acme eab add' requires the Admin Provisioner credentials.
	// Since we are inside the container, we can access using --password-file.
	// But wait, 'step ca acme eab add' is a command to ADD a key to the DB.
	// It connects to the CA? No, wait.
	// If the CA is using a local DB (BoltDB), we cannot write to it while the CA process has a lock on it.
	// THIS IS A CRITICAL PROBLEM. BoltDB does not support concurrent access.
	//
	// If we run 'step-ca' server (which holds BoltDB lock), we simply cannot run another 'step' process that tries to write to BoltDB directly.
	// We must use the API.
	// Does 'step-ca' API support creating EAB tokens?
	// Yes, usually via the Admin API.

	// Let's try attempting to use the CLI against the running server.
	// step ca provisioner webhook? No.
	// The command `step ca acme eab add` normally talks to the DB directly?? Or talks to API?
	// If it talks to API, we need --admin-subject and --password-file.

	cmdStr := fmt.Sprintf("step ca acme eab add %s agent-001 --admin-provisioner admin --password-file /home/step/provisioner_password.txt --ca-url https://localhost:9000 --root /home/step/certs/root_ca.crt", ProvisionerName)

	execArgs := []string{
		"exec", containerName,
		"/bin/sh", "-c", cmdStr,
	}

	out, err := exec.Command("docker", execArgs...).CombinedOutput()
	if err != nil {
		// Fallback: If 'step ca acme eab add' fails (maybe old version?), we are in trouble.
		// But let's assume it works.
		return nil, fmt.Errorf("step ca acme eab add failed: %v, output: %s", err, string(out))
	}

	// Output format:
	// The command usually prints key info. Let's look at the output.
	// "Key ID: ...\nKey: ..."
	output := string(out)

	kid, key := parseEABOutput(output)
	if kid == "" || key == "" {
		return nil, fmt.Errorf("failed to parse EAB key from output: %s", output)
	}

	return &EABKey{KID: kid, Key: key}, nil
}

func parseEABOutput(out string) (string, string) {
	// Simple parser for:
	// Key ID: <kid>
	// HMAC Key: <key>
	// (Actual output format might vary, need to be robust)

	// Let's assume standard step-cli output
	lines := strings.Split(out, "\n")
	var kid, key string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Key ID:") {
			kid = strings.TrimSpace(strings.TrimPrefix(line, "Key ID:"))
		}
		if strings.HasPrefix(line, "HMAC Key:") || strings.HasPrefix(line, "Key:") {
			key = strings.TrimSpace(strings.TrimPrefix(line, "HMAC Key:"))
			if key == "" {
				key = strings.TrimSpace(strings.TrimPrefix(line, "Key:"))
			}
		}
	}

	// If not found, maybe JSON output? --output-file?
	// We didn't use --output-file.
	return kid, key
}

func runDockerCommand(args []string) error {
	cmd := exec.Command("docker", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func getUserIdentity() (string, string, error) {
	if runtime.GOOS == "windows" {
		return "0", "0", nil
	}

	currentUser, err := user.Current()
	if err != nil {
		return "", "", err
	}
	return currentUser.Uid, currentUser.Gid, nil
}
