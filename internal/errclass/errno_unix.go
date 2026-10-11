//go:build !windows

package errclass

import "syscall"

func isReset(e syscall.Errno) bool {
	return e == syscall.ECONNRESET || e == syscall.ECONNABORTED || e == syscall.EPIPE
}

func isRefused(e syscall.Errno) bool { return e == syscall.ECONNREFUSED }

func isTimeout(e syscall.Errno) bool { return e == syscall.ETIMEDOUT }

func isUnreachable(e syscall.Errno) bool {
	return e == syscall.ENETUNREACH || e == syscall.EHOSTUNREACH || e == syscall.ENETDOWN || e == syscall.EHOSTDOWN
}
