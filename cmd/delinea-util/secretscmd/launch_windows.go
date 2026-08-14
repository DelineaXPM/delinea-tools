//go:build windows

package secretscmd

// Windows has no exec-replace, so every launch spawns the child and streams.
func launch(command []string, env []string, payload []byte) error {
	return streamLaunch(command, env, payload)
}
