package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
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

	// Define secrets directory path (relative to where command is run or project root)
	// Assuming this tool is run from the project root.
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

	if err := ioutil.WriteFile(passwordFile, []byte("password123\n"), 0600); err != nil {
		return fmt.Errorf("writing password file: %w", err)
	}
	if err := ioutil.WriteFile(provisionerPasswordFile, []byte("sysadmin-password123\n"), 0600); err != nil {
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

	// 2. Add ACME Provisioner
	fmt.Println("Adding ACME Provisioner...")
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

	fmt.Println("Bootroot CA initialization complete.")
	fmt.Printf("Configuration and keys are in %s\n", secretsDir)

	return nil
}

func runDockerCommand(args []string) error {
	cmd := exec.Command("docker", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func getUserIdentity() (string, string, error) {
	if runtime.GOOS == "windows" {
		// On Windows, file permissions with Docker volumes behave differently.
		// For now, valid UID/GID might not be strict or needed in default Docker Desktop setup.
		// Returning 0:0 or handling specifically might be needed.
		// For MVP, assuming Linux/Mac environment as per user metadata.
		return "0", "0", nil
	}

	currentUser, err := user.Current()
	if err != nil {
		return "", "", err
	}
	return currentUser.Uid, currentUser.Gid, nil
}
