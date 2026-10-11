// Package model defines the measurement and report data structures shared by
// probes, the classifier, renderers and the submission format.
//
// Everything here is serialised to JSON; field names are part of the public
// report format (schema prosvet.report/v1) and must stay backwards compatible.
package model

import "time"

// ReportSchema identifies the JSON report format.
const ReportSchema = "prosvet.report/v1"

// Outcome is the result code of a single probe step.
type Outcome string

// Probe outcomes.
const (
	OK          Outcome = "ok"
	Timeout     Outcome = "timeout"
	Reset       Outcome = "reset"
	Refused     Outcome = "refused"
	EOF         Outcome = "eof"
	Unreachable Outcome = "unreachable"
	NXDomain    Outcome = "nxdomain"
	ServFail    Outcome = "servfail"
	NoAnswer    Outcome = "no_answer"
	TLSAlert    Outcome = "tls_alert"
	Stall       Outcome = "stall"
	Responded   Outcome = "responded" // QUIC: the server answered but the handshake did not complete
	Unsupported Outcome = "unsupported"
	Error       Outcome = "error"
	Skipped     Outcome = "skipped"
)

// Interfered reports whether an outcome is a typical sign of on-path interference
// (as opposed to a normal server response).
func (o Outcome) Interfered() bool {
	switch o {
	case Timeout, Reset, EOF, Stall:
		return true
	}
	return false
}

// ServerAnswered reports whether the remote server demonstrably answered.
func (o Outcome) ServerAnswered() bool {
	return o == OK || o == TLSAlert || o == Responded || o == Unsupported
}

// Kind is the type of interference identified by the classifier.
type Kind string

// Verdict kinds. The order of the list is the display priority.
const (
	KindOK             Kind = "ok"
	KindNoConnectivity Kind = "no_connectivity"
	KindTLSMITM        Kind = "tls_mitm"
	KindBlockpage      Kind = "blockpage"
	KindDNS            Kind = "dns"
	KindSNIDPI         Kind = "sni_dpi"
	KindIPBlock        Kind = "ip_block"
	KindTLSReset       Kind = "tls_reset"
	KindThrottleFreeze Kind = "throttle_freeze"
	KindThrottleRate   Kind = "throttle_rate"
	KindQUICSNI        Kind = "quic_sni"
	KindQUICBlocked    Kind = "quic_blocked"
	KindECHBlocked     Kind = "ech_blocked"
	KindTimeout        Kind = "timeout"
	KindUnknown        Kind = "unknown"
)

// AllKinds lists every verdict kind in display priority order.
var AllKinds = []Kind{
	KindNoConnectivity, KindTLSMITM, KindBlockpage, KindDNS, KindSNIDPI, KindIPBlock,
	KindTLSReset, KindThrottleFreeze, KindThrottleRate, KindQUICSNI, KindQUICBlocked,
	KindECHBlocked, KindTimeout, KindUnknown, KindOK,
}

// IsBlocking reports whether the kind means the resource is not usable.
func (k Kind) IsBlocking() bool {
	switch k {
	case KindTLSMITM, KindBlockpage, KindDNS, KindSNIDPI, KindIPBlock, KindTLSReset, KindTimeout:
		return true
	}
	return false
}

// IsThrottling reports whether the kind is a slowdown rather than a block.
func (k Kind) IsThrottling() bool {
	return k == KindThrottleFreeze || k == KindThrottleRate
}

// IsProtocol reports whether the kind only concerns an alternative protocol (QUIC, ECH).
func (k Kind) IsProtocol() bool {
	return k == KindQUICSNI || k == KindQUICBlocked || k == KindECHBlocked
}

// Confidence of a verdict.
type Confidence string

// Confidence levels.
const (
	High   Confidence = "high"
	Medium Confidence = "medium"
	Low    Confidence = "low"
)

// Rank orders confidence levels (higher is more confident).
func (c Confidence) Rank() int {
	switch c {
	case High:
		return 3
	case Medium:
		return 2
	case Low:
		return 1
	}
	return 0
}

// Lower returns the next lower confidence level.
func (c Confidence) Lower() Confidence {
	switch c {
	case High:
		return Medium
	default:
		return Low
	}
}

// Status is the user-facing state of a target.
type Status string

// Target statuses.
const (
	StatusOK          Status = "ok"
	StatusThrottled   Status = "throttled"
	StatusPartial     Status = "partial"
	StatusBlocked     Status = "blocked"
	StatusUnreachable Status = "unreachable" // the whole network is down, nothing can be said
	StatusUnknown     Status = "unknown"
)

// Evidence is one localisable line explaining a verdict.
type Evidence struct {
	Key  string            `json:"key"`
	Args map[string]string `json:"args,omitempty"`
}

// Verdict is the classifier output for an endpoint or a target.
type Verdict struct {
	Kind       Kind       `json:"kind"`
	Subtype    string     `json:"subtype,omitempty"`
	Confidence Confidence `json:"confidence"`
	Evidence   []Evidence `json:"evidence,omitempty"`
}

// DNSAnswer is the result of resolving a name through one resolver.
type DNSAnswer struct {
	Resolver string   `json:"resolver"`
	Outcome  Outcome  `json:"outcome"`
	Addrs    []string `json:"addrs,omitempty"`
	Stub     string   `json:"stub,omitempty"` // fingerprint id when the answer is a known block stub
	Bogon    bool     `json:"bogon,omitempty"`
	RTTMs    int64    `json:"rtt_ms,omitempty"`
	Error    string   `json:"error,omitempty"`
	Agree    int      `json:"agree,omitempty"`
	Runs     int      `json:"runs,omitempty"`
}

// DNSResult groups the answers gathered for one endpoint.
type DNSResult struct {
	System    DNSAnswer  `json:"system"`
	NSDI      *DNSAnswer `json:"nsdi,omitempty"`
	Reference *DNSAnswer `json:"reference,omitempty"`
}

// CertInfo summarises the certificate presented during a TLS handshake.
type CertInfo struct {
	Subject          string    `json:"subject,omitempty"`
	Issuer           string    `json:"issuer,omitempty"`
	ValidForHost     bool      `json:"valid_for_host"`
	TrustedSystem    bool      `json:"trusted_system"`
	RussianTrustedCA bool      `json:"russian_trusted_ca,omitempty"`
	NotAfter         time.Time `json:"not_after,omitempty"`
}

// TLS probe variants.
const (
	VariantReal   = "real"
	VariantNone   = "none"
	VariantRandom = "random"
	VariantECH    = "ech"
)

// TLSResult is a single TLS attempt (TCP connect + handshake).
type TLSResult struct {
	Variant     string    `json:"variant"`
	Stage       string    `json:"stage"` // "connect" or "handshake"
	Outcome     Outcome   `json:"outcome"`
	ConnectMs   int64     `json:"connect_ms,omitempty"`
	HandshakeMs int64     `json:"handshake_ms,omitempty"`
	Version     string    `json:"version,omitempty"`
	ECHAccepted bool      `json:"ech_accepted,omitempty"`
	Cert        *CertInfo `json:"cert,omitempty"`
	Error       string    `json:"error,omitempty"`
	Agree       int       `json:"agree,omitempty"`
	Runs        int       `json:"runs,omitempty"`
}

// Key is the value used for majority voting.
func (r *TLSResult) Key() string { return r.Stage + ":" + string(r.Outcome) }

// Succeeded reports whether the handshake completed.
func (r *TLSResult) Succeeded() bool { return r != nil && r.Stage == "handshake" && r.Outcome == OK }

// HTTPResult is a single HTTP exchange.
type HTTPResult struct {
	Outcome          Outcome `json:"outcome"`
	Status           int     `json:"status,omitempty"`
	Bytes            int64   `json:"bytes"`                // body bytes
	RawBytes         int64   `json:"raw_bytes"`            // application bytes incl. headers
	WireBytes        int64   `json:"wire_bytes,omitempty"` // TCP payload bytes incl. TLS handshake
	ContentLength    int64   `json:"content_length"`
	Complete         bool    `json:"complete"`
	Truncated        bool    `json:"truncated,omitempty"`
	Stalled          bool    `json:"stalled,omitempty"`
	BytesBeforeStall int64   `json:"bytes_before_stall,omitempty"` // wire bytes when the transfer froze
	TTFBMs           int64   `json:"ttfb_ms,omitempty"`
	DurationMs       int64   `json:"duration_ms,omitempty"`
	ThroughputKbps   float64 `json:"throughput_kbps,omitempty"`
	Location         string  `json:"location,omitempty"`
	Blockpage        string  `json:"blockpage,omitempty"`
	Error            string  `json:"error,omitempty"`
	Agree            int     `json:"agree,omitempty"`
	Runs             int     `json:"runs,omitempty"`
	StallRuns        int     `json:"stall_runs,omitempty"`
}

// QUICResult is a QUIC handshake attempt.
type QUICResult struct {
	Version int     `json:"version"`
	Variant string  `json:"variant"`
	Outcome Outcome `json:"outcome"`
	RTTMs   int64   `json:"rtt_ms,omitempty"`
	Error   string  `json:"error,omitempty"`
	Agree   int     `json:"agree,omitempty"`
	Runs    int     `json:"runs,omitempty"`
}

// EndpointResult aggregates all probes of one endpoint (after majority voting).
type EndpointResult struct {
	Name      string        `json:"name"`
	Port      int           `json:"port"`
	IP        string        `json:"ip,omitempty"` // server address that was tested
	IPSource  string        `json:"ip_source,omitempty"`
	Note      string        `json:"note,omitempty"`
	DNS       *DNSResult    `json:"dns,omitempty"`
	TCP       *TLSResult    `json:"tcp,omitempty"` // connect-only endpoints
	TLS       []*TLSResult  `json:"tls,omitempty"`
	RefTLS    *TLSResult    `json:"ref_tls,omitempty"` // real-SNI handshake to the address from the reference resolver
	HTTP      *HTTPResult   `json:"http,omitempty"`
	HTTP80    *HTTPResult   `json:"http80,omitempty"`
	QUIC      []*QUICResult `json:"quic,omitempty"`
	ECH       *TLSResult    `json:"ech,omitempty"`
	Verdict   Verdict       `json:"verdict"`
	Secondary []Kind        `json:"secondary,omitempty"`
	// ProtocolFocus marks endpoints whose purpose is a protocol probe (QUIC,
	// ECH); their TCP/TLS handshake only serves as a control.
	ProtocolFocus bool `json:"protocol_focus,omitempty"`
}

// TLSVariant returns the aggregated TLS result for a variant, or nil.
func (e *EndpointResult) TLSVariant(v string) *TLSResult {
	for _, t := range e.TLS {
		if t.Variant == v {
			return t
		}
	}
	return nil
}

// TargetResult is the outcome for one target (service).
type TargetResult struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Category    string           `json:"category"`
	Role        string           `json:"role,omitempty"`
	Expect      string           `json:"expect,omitempty"`
	Since       string           `json:"since,omitempty"`
	Status      Status           `json:"status"`
	Verdict     Verdict          `json:"verdict"`
	Secondary   []Kind           `json:"secondary,omitempty"`
	Endpoints   []EndpointResult `json:"endpoints"`
	ThrottleURL string           `json:"throttle_url,omitempty"`
	Throttle    *HTTPResult      `json:"throttle,omitempty"`
	DurationMs  int64            `json:"duration_ms"`
}

// NetworkInfo describes the user's network. It never contains the user's IP address.
type NetworkInfo struct {
	ASN          int    `json:"asn,omitempty"`
	ISP          string `json:"isp,omitempty"`
	Country      string `json:"country,omitempty"`
	Region       string `json:"region,omitempty"` // ISO 3166-2 code, e.g. RU-MOW
	RegionName   string `json:"region_name,omitempty"`
	Conn         string `json:"conn"` // mobile | fixed | unknown
	ConnSource   string `json:"conn_source,omitempty"`
	VPNSuspected bool   `json:"vpn_suspected,omitempty"`
	VPNReason    string `json:"vpn_reason,omitempty"`
	ProxyIgnored bool   `json:"proxy_ignored,omitempty"`
	Source       string `json:"source,omitempty"` // auto | manual | none
	Error        string `json:"error,omitempty"`
}

// ResolverStatus is the reachability of one resolver transport.
type ResolverStatus struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Transport string  `json:"transport"` // system | udp | dot | doh
	Endpoint  string  `json:"endpoint"`
	Outcome   Outcome `json:"outcome"`
	RTTMs     int64   `json:"rtt_ms,omitempty"`
	Error     string  `json:"error,omitempty"`
}

// DomainCheck compares answers for one probe domain across resolvers.
type DomainCheck struct {
	Name    string      `json:"name"`
	Role    string      `json:"role,omitempty"`
	Answers []DNSAnswer `json:"answers"`
}

// InterceptionCheck is one transparent-DNS-proxy probe.
type InterceptionCheck struct {
	ID       string  `json:"id"`
	Resolver string  `json:"resolver"`
	QName    string  `json:"qname"`
	Expect   string  `json:"expect"`
	Outcome  Outcome `json:"outcome"`
	Passed   bool    `json:"passed"`
	Detail   string  `json:"detail,omitempty"` // never contains the user's IP
}

// DNSFinding is a conclusion drawn from the DNS checks.
type DNSFinding struct {
	Kind       string     `json:"kind"` // dns_interception | doh_blocked | dot_blocked | udp_blocked | nsdi_divergence
	Resolvers  []string   `json:"resolvers,omitempty"`
	Domains    []string   `json:"domains,omitempty"`
	Confidence Confidence `json:"confidence"`
}

// DNSReport is the output of the resolver matrix and interception checks.
type DNSReport struct {
	Resolvers    []ResolverStatus    `json:"resolvers"`
	Domains      []DomainCheck       `json:"domains"`
	Interception []InterceptionCheck `json:"interception"`
	Findings     []DNSFinding        `json:"findings,omitempty"`
}

// WhitelistCheck is one host checked in whitelist mode.
type WhitelistCheck struct {
	Host    string  `json:"host"`
	Org     string  `json:"org,omitempty"`
	Stage   string  `json:"stage"` // dns | connect | handshake | ok
	Outcome Outcome `json:"outcome"`
	CA      string  `json:"ca,omitempty"`
}

// Whitelist verdicts.
const (
	WhitelistActive         = "active"
	WhitelistNormal         = "normal"
	WhitelistNoConnectivity = "no_connectivity"
	WhitelistDegraded       = "degraded"
)

// WhitelistResult is the outcome of `prosvet whitelist`.
type WhitelistResult struct {
	Verdict       string           `json:"verdict"`
	Confidence    Confidence       `json:"confidence"`
	DomesticOK    int              `json:"domestic_ok"`
	DomesticTotal int              `json:"domestic_total"`
	ForeignOK     int              `json:"foreign_ok"`
	ForeignTotal  int              `json:"foreign_total"`
	FailureLevel  string           `json:"failure_level,omitempty"` // dns | connect | handshake | mixed
	Domestic      []WhitelistCheck `json:"domestic"`
	Foreign       []WhitelistCheck `json:"foreign"`
}

// Baseline is the domestic throughput reference used for throttling detection.
type Baseline struct {
	Kbps   float64 `json:"kbps"`
	Source string  `json:"source"`
}

// ToolInfo identifies the producing tool.
type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

// ScanOptions records how a scan was run.
type ScanOptions struct {
	Repeats    int      `json:"repeats"`
	Categories []string `json:"categories,omitempty"`
	Targets    []string `json:"targets,omitempty"`
	QUIC       bool     `json:"quic"`
	Demo       bool     `json:"demo,omitempty"`
}

// Summary counts targets by status.
type Summary struct {
	Total       int `json:"total"`
	OK          int `json:"ok"`
	Throttled   int `json:"throttled"`
	Partial     int `json:"partial"`
	Blocked     int `json:"blocked"`
	Unreachable int `json:"unreachable"`
	Unknown     int `json:"unknown"`
}

// Report is the complete result of a scan.
type Report struct {
	Schema       string           `json:"schema"`
	Tool         ToolInfo         `json:"tool"`
	StartedAt    time.Time        `json:"started_at"`
	FinishedAt   time.Time        `json:"finished_at"`
	Options      ScanOptions      `json:"options"`
	Network      NetworkInfo      `json:"network"`
	Connectivity *Verdict         `json:"connectivity,omitempty"`
	Baseline     *Baseline        `json:"baseline,omitempty"`
	Targets      []TargetResult   `json:"targets"`
	DNS          *DNSReport       `json:"dns,omitempty"`
	Whitelist    *WhitelistResult `json:"whitelist,omitempty"`
	Summary      Summary          `json:"summary"`
}

// Recount recomputes the summary from target statuses. Baseline and control
// targets are excluded from the counts.
func (r *Report) Recount() {
	s := Summary{}
	for _, t := range r.Targets {
		if t.Role == "baseline" {
			continue
		}
		s.Total++
		switch t.Status {
		case StatusOK:
			s.OK++
		case StatusThrottled:
			s.Throttled++
		case StatusPartial:
			s.Partial++
		case StatusBlocked:
			s.Blocked++
		case StatusUnreachable:
			s.Unreachable++
		default:
			s.Unknown++
		}
	}
	r.Summary = s
}
