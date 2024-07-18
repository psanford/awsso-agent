//go:build !linux
// +build !linux

package notify

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

func showNotification(message string) func() {
	clearFunc := func() {
	}

	switch runtime.GOOS {
	case "darwin":
		message = strings.ReplaceAll(message, `\`, `\\`)
		message = strings.ReplaceAll(message, `"`, `\"`)
		appleScript := `display notification "%s" with title "awsso"`
		exec.Command("osascript", "-e", fmt.Sprintf(appleScript, message)).Run()
	}

	return clearFunc
}
