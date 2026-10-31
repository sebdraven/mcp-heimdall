package heimdall

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// KeychainService is where the token is looked for on macOS.
const KeychainService = "mcp-heimdall"

// Token finds the Heimdall API token: the environment first, then the macOS
// keychain so it need not sit in cleartext in a client's config file.
func Token() (string, error) {
	if t := strings.TrimSpace(os.Getenv("HEIMDALL_TOKEN")); t != "" {
		return t, nil
	}
	if runtime.GOOS == "darwin" {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "security", "find-generic-password",
			"-s", KeychainService, "-w").Output()
		if err == nil {
			if t := strings.TrimSpace(string(out)); t != "" {
				return t, nil
			}
		}
	}
	return "", fmt.Errorf("no Heimdall token: set HEIMDALL_TOKEN.\n" +
		"Create one with: heimdall-cli token create --username <user> --label mcp\n" +
		"On macOS it can instead be stored in the keychain under the service name " + KeychainService)
}
