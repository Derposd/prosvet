//go:build windows

package errclass

import "syscall"

// Winsock error codes (winerror.h).
const (
	wsaeNetDown     syscall.Errno = 10050
	wsaeNetUnreach  syscall.Errno = 10051
	wsaeConnAborted syscall.Errno = 10053
	wsaeConnReset   syscall.Errno = 10054
	wsaeTimedOut    syscall.Errno = 10060
	wsaeConnRefused syscall.Errno = 10061
	wsaeHostDown    syscall.Errno = 10064
	wsaeHostUnreach syscall.Errno = 10065
	errorNetUnreach syscall.Errno = 1231 // ERROR_NETWORK_UNREACHABLE
	errorConnRefuse syscall.Errno = 1225 // ERROR_CONNECTION_REFUSED
)

func isReset(e syscall.Errno) bool {
	return e == wsaeConnReset || e == wsaeConnAborted || e == syscall.ECONNRESET
}

func isRefused(e syscall.Errno) bool {
	return e == wsaeConnRefused || e == errorConnRefuse || e == syscall.ECONNREFUSED
}

func isTimeout(e syscall.Errno) bool { return e == wsaeTimedOut || e == syscall.ETIMEDOUT }

func isUnreachable(e syscall.Errno) bool {
	return e == wsaeNetUnreach || e == wsaeHostUnreach || e == wsaeNetDown || e == wsaeHostDown || e == errorNetUnreach
}
