// Package brand holds the Prosvet logo so every output embeds the same mark.
//
// The logo shows a wall with a gap ("просвет") and a beam of light passing
// through it: Prosvet measures what gets through.
package brand

import (
	"encoding/base64"
	"strings"
)

// Repo is the GitHub repository slug ("owner/name").
const Repo = "Derposd/prosvet"

// RepoURL is the project homepage.
const RepoURL = "https://github.com/" + Repo

// MapURL is the public map on GitHub Pages.
const MapURL = "https://derposd.github.io/prosvet/"

// LogoSVG is the square logo (64×64 viewBox).
const LogoSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img" aria-label="Prosvet"><defs><linearGradient id="pv-ray" x1="0" x2="1" y1="0" y2="0"><stop offset="0" stop-color="#7C9CFF" stop-opacity=".1"/><stop offset=".45" stop-color="#7C9CFF"/><stop offset="1" stop-color="#B9F2FF"/></linearGradient></defs><rect width="64" height="64" rx="14" fill="#0D1117"/><path d="M6 30.2 30 29.4v5.2L6 33.8z" fill="url(#pv-ray)" opacity=".55"/><path d="M34 29.4 58 19v26L34 34.6z" fill="url(#pv-ray)"/><rect x="28.5" y="9" width="7" height="18.5" rx="2.2" fill="#E6EDF3"/><rect x="28.5" y="36.5" width="7" height="18.5" rx="2.2" fill="#E6EDF3"/></svg>`

// FaviconDataURI returns the logo as a data: URI for <link rel="icon">.
func FaviconDataURI() string {
	return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(LogoSVG))
}

// LogoWithID returns the logo with a unique gradient id, for pages that
// embed it more than once.
func LogoWithID(id string) string {
	return strings.ReplaceAll(LogoSVG, "pv-ray", "pv-ray-"+id)
}
