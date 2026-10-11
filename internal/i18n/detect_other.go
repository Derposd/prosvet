//go:build !windows

package i18n

// On Unix-like systems the locale environment variables are authoritative;
// they are checked in Detect.
func osLanguage() string { return "" }
