//go:build !windows

package secretscmd

import "syscall"

// oNoFollow refuses to open a final path component that is a symlink, closing
// the window between the pre-write Lstat and the open. Unix only; see the
// windows variant for why it is zero there.
const oNoFollow = syscall.O_NOFOLLOW
