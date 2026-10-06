//go:build !linux

package nodeaccess

import (
	"context"
	"fmt"
)

func runLocalPTY(context.Context, int, int, <-chan ShellMessage, *shellWriter) (int, error) {
	return -1, fmt.Errorf("interactive node sessions are supported only on Linux guests")
}
