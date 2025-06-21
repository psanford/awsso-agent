//go:build !macos
// +build !macos

package pinentry

import "context"

func confirmOSAScript(ctx context.Context, prompt string) (bool, error) {
	panic("confirmOSAScript only implemented for macos")
}
