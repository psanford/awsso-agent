package pinentry

import (
	"context"
	"fmt"
	"os/exec"

	assuan "github.com/foxcpp/go-assuan/client"
	"github.com/foxcpp/go-assuan/pinentry"
)

func GetPin(prompt string) (string, error) {
	childCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, cmd, err := launch(childCtx)
	if err != nil {
		return "", fmt.Errorf("failed to start pinentry: %w", err)
	}
	defer func() {
		cancel()
		cmd.Wait()
	}()

	defer p.Shutdown()
	p.SetTitle("AWSSO")
	p.SetPrompt("AWSSO")
	p.SetDesc(prompt)
	pin, err := p.GetPIN()

	return pin, err
}

func Confirm(ctx context.Context, prompt string) (bool, error) {
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	p, cmd, err := launch(childCtx)
	if err != nil {
		return false, fmt.Errorf("failed to start pinentry: %w", err)
	}
	defer func() {
		cancel()
		cmd.Wait()
	}()

	defer p.Shutdown()
	p.SetTitle("AWSSO")
	p.SetPrompt("AWSSO")
	p.SetDesc(prompt)

	result := make(chan bool)

	go func() {
		err := p.Confirm()
		result <- err == nil
	}()

	select {
	case ok := <-result:
		return ok, nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

func launch(ctx context.Context) (*pinentry.Client, *exec.Cmd, error) {
	cmd := exec.CommandContext(ctx, "pinentry")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}

	var c pinentry.Client
	c.Session, err = assuan.Init(assuan.ReadWriteCloser{
		ReadCloser:  stdout,
		WriteCloser: stdin,
	})

	if err != nil {
		return nil, nil, err
	}
	return &c, cmd, nil
}
