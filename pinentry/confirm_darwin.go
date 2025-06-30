//go:build darwin
// +build darwin

package pinentry

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
)

func confirmOSAScript(ctx context.Context, prompt string) (bool, error) {
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	osaCmd := fmt.Sprintf(`display dialog %s buttons {"Cancel", "OK"} default button "OK"`, strconv.Quote(prompt))

	cmd := exec.CommandContext(childCtx, "osascript", "-e", osaCmd)

	err := cmd.Run()
	return err == nil, err
}
