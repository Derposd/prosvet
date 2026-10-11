// Package netinfo determines the user's network: ASN, provider, coarse region
// and connection type. The public IP address is only held in memory long
// enough to look these up and is never stored or returned.
package netinfo

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ordinarysim/prosvet/internal/model"
)

// Options configure detection. Manual values override automatic ones.
type Options struct {
	ASN     int
	ISP     string
	Region  string
	Conn    string
	Offline bool // do not contact any lookup service
	Lang    string

	// Client performs lookups; it must not use proxies. Required unless Offline.
	Client *http.Client
	// RIPEstat and echo service base URLs (overridable in tests).
	RIPEBase string
	EchoURLs []string
	// Local overrides interface detection (tests).
	Local *LocalInfo
}

// DefaultRIPEBase is the RIPEstat Data API.
const DefaultRIPEBase = "https://stat.ripe.net/data"

// DefaultEchoURLs return the caller's public address. A domestic service is
// listed first so that detection still works in whitelist mode.
var DefaultEchoURLs = []string{
	"https://yandex.ru/internet/api/v0/ip",
	DefaultRIPEBase + "/whats-my-ip/data.json",
	"https://www.cloudflare.com/cdn-cgi/trace",
}

// Detect gathers network information.
func Detect(ctx context.Context, opt Options) model.NetworkInfo {
	info := model.NetworkInfo{Conn: "unknown", Source: "auto"}
	local := DetectLocal()
	if opt.Local != nil {
		local = *opt.Local
	}
	info.ProxyIgnored = ProxyEnvSet()
	if local.VPN {
		info.VPNSuspected, info.VPNReason = true, local.VPNReason
	}

	if !opt.Offline && opt.Client != nil {
		if err := lookup(ctx, opt, &info); err != nil {
			info.Error = err.Error()
		}
	} else {
		info.Source = "none"
	}

	// Connection type: interface evidence beats ASN hints.
	switch {
	case local.Cellular:
		info.Conn, info.ConnSource = "mobile", "interface"
	case info.ASN != 0 && asnConn[info.ASN] == "mobile":
		info.Conn, info.ConnSource = "mobile", "asn"
	case info.ASN != 0 && asnConn[info.ASN] == "fixed":
		info.Conn, info.ConnSource = "fixed", "asn"
	}

	// Manual overrides.
	if opt.ASN != 0 {
		info.ASN, info.Source = opt.ASN, "manual"
	}
	if opt.ISP != "" {
		info.ISP = opt.ISP
	}
	if opt.Region != "" {
		info.Region = strings.ToUpper(opt.Region)
		info.RegionName = ""
		if r := RegionByCode(info.Region); r != nil {
			info.RegionName = regionName(r, opt.Lang)
			info.Country = "RU"
		}
	}
	if opt.Conn != "" {
		info.Conn, info.ConnSource = opt.Conn, "manual"
	}
	return info
}

func regionName(r *Region, lang string) string {
	if lang == "ru" {
		return r.RU
	}
	return r.EN
}

func lookup(ctx context.Context, opt Options, info *model.NetworkInfo) error {
	base := opt.RIPEBase
	if base == "" {
		base = DefaultRIPEBase
	}
	echo := opt.EchoURLs
	if len(echo) == 0 {
		echo = DefaultEchoURLs
	}
	ip, err := publicIP(ctx, opt.Client, echo)
	if err != nil {
		return err
	}
	// From here on the address is only passed to RIPEstat and then dropped.
	var ni struct {
		Data struct {
			ASNs []string `json:"asns"`
		} `json:"data"`
	}
	if err := getJSON(ctx, opt.Client, base+"/network-info/data.json?resource="+ip, &ni); err != nil {
		return fmt.Errorf("asn lookup: %w", err)
	}
	if len(ni.Data.ASNs) > 0 {
		info.ASN, _ = strconv.Atoi(ni.Data.ASNs[0])
	}
	if info.ASN != 0 {
		var ov struct {
			Data struct {
				Holder string `json:"holder"`
			} `json:"data"`
		}
		if err := getJSON(ctx, opt.Client, base+"/as-overview/data.json?resource=AS"+strconv.Itoa(info.ASN), &ov); err == nil {
			info.ISP = cleanHolder(ov.Data.Holder)
			if isHosting(ov.Data.Holder) && !info.VPNSuspected {
				info.VPNSuspected, info.VPNReason = true, "public address belongs to a hosting provider"
			}
		}
	}
	var geo struct {
		Data struct {
			Located []struct {
				Locations []struct {
					Country string  `json:"country"`
					Lat     float64 `json:"latitude"`
					Lon     float64 `json:"longitude"`
				} `json:"locations"`
			} `json:"located_resources"`
		} `json:"data"`
	}
	if err := getJSON(ctx, opt.Client, base+"/maxmind-geo-lite/data.json?resource="+ip, &geo); err == nil {
		if len(geo.Data.Located) > 0 && len(geo.Data.Located[0].Locations) > 0 {
			l := geo.Data.Located[0].Locations[0]
			info.Country = l.Country
			if l.Country == "RU" {
				if r := NearestRegion(l.Lat, l.Lon); r != nil {
					info.Region, info.RegionName = r.Code, regionName(r, opt.Lang)
				}
			}
		}
	}
	return nil
}

func publicIP(ctx context.Context, c *http.Client, urls []string) (string, error) {
	var errs []error
	for _, u := range urls {
		ip, err := echoIP(ctx, c, u)
		if err == nil {
			return ip, nil
		}
		errs = append(errs, err)
	}
	return "", fmt.Errorf("public address lookup failed: %w", errors.Join(errs...))
}

func echoIP(ctx context.Context, c *http.Client, url string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: status %d", req.URL.Host, resp.StatusCode)
	}
	s := strings.TrimSpace(string(body))
	// RIPEstat whats-my-ip
	var ripe struct {
		Data struct {
			IP string `json:"ip"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &ripe) == nil && net.ParseIP(ripe.Data.IP) != nil {
		return ripe.Data.IP, nil
	}
	// Yandex: a JSON string
	var str string
	if json.Unmarshal(body, &str) == nil && net.ParseIP(str) != nil {
		return str, nil
	}
	// Cloudflare trace: key=value lines
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "ip="); ok && net.ParseIP(v) != nil {
			return v, nil
		}
	}
	if net.ParseIP(s) != nil {
		return s, nil
	}
	return "", fmt.Errorf("%s: no address in response", req.URL.Host)
}

func getJSON(ctx context.Context, c *http.Client, url string, v any) error {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v)
}
