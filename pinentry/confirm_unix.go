//go:build !darwin
// +build !darwin

package pinentry

import "context"

func confirmOSAScript(ctx context.Context, prompt string) (bool, error) {
	panic("confirmOSAScript only implemented for macos")
}
