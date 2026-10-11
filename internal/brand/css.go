package brand

import _ "embed"

// CSS is the shared stylesheet (report, dashboard, public map).
//
//go:embed prosvet.css
var CSS string
