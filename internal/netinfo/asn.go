package netinfo

import "strings"

// Connection type hints for well-known Russian networks. "mixed" networks
// serve both mobile and home customers, so the ASN alone is not conclusive.
// Holder names were verified with RIPEstat (2026-10).
var asnConn = map[int]string{
	// mobile
	31133: "mobile", // PJSC MegaFon (MF-MGSM)
	25159: "mobile", // PJSC MegaFon (Sonicduo)
	47395: "mobile", // Scartel / Yota (MegaFon)
	12958: "mobile", // T2 Mobile
	15378: "mobile", // T2 Mobile
	48092: "mobile", // T2 Mobile
	16345: "mobile", // PJSC Vimpelcom (Beeline mobile)
	// mixed
	8359:  "mixed", // MTS PJSC
	29497: "mixed", // MTS PJSC (Kuban)
	39811: "mixed", // MTS PJSC (Far East)
	3216:  "mixed", // PJSC Vimpelcom
	// fixed
	12389: "fixed", // PJSC Rostelecom
	42610: "fixed", // PJSC Rostelecom
	21479: "fixed", // PJSC Rostelecom (Rostov)
	8402:  "fixed", // Beeline home internet (Corbina)
	25513: "fixed", // MGTS
	9049:  "fixed", // ER-Telecom (Dom.ru)
	41733: "fixed", // ER-Telecom
	35807: "fixed", // SkyNet (St. Petersburg)
	20485: "fixed", // TransTeleCom
}

// hostingHints mark ASNs whose holder name suggests a datacenter, i.e. the
// measurement probably runs through a VPN, proxy or remote server.
var hostingHints = []string{
	"hetzner", "digitalocean", "ovh", "amazon", "aws", "google", "cloudflare", "microsoft",
	"m247", "datacamp", "contabo", "vultr", "choopa", "linode", "akamai", "leaseweb", "aeza",
	"hosting", "datacenter", "data center", "vps", "server", "colocation", "g-core", "gcore",
	"stark industries", "pq hosting", "timeweb", "selectel", "firstbyte", "ihc", "beget",
}

func isHosting(holder string) bool {
	h := strings.ToLower(holder)
	for _, k := range hostingHints {
		if strings.Contains(h, k) {
			return true
		}
	}
	return false
}

// cleanHolder turns "ROSTELECOM-AS PJSC Rostelecom" into "PJSC Rostelecom".
func cleanHolder(h string) string {
	h = strings.TrimSpace(h)
	parts := strings.SplitN(h, " ", 2)
	if len(parts) == 2 && parts[0] == strings.ToUpper(parts[0]) && strings.ContainsAny(parts[0], "-") {
		return strings.TrimSpace(parts[1])
	}
	return h
}
