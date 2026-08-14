//go:build windows

package secretscmd

// Windows has no O_NOFOLLOW; the os.SameFile check after opening is the
// portable guard against the target changing between Lstat and open.
const oNoFollow = 0
