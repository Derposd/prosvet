package mapgen

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Derposd/prosvet/internal/catalog"
	"github.com/Derposd/prosvet/internal/model"
	"github.com/Derposd/prosvet/internal/netinfo"
)

// Data is the JSON consumed by the map front-end.
type Data struct {
	Generated   string                       `json:"generated"`
	Updated     string                       `json:"updated,omitempty"`
	Sample      bool                         `json:"sample,omitempty"`
	Submissions int                          `json:"submissions"`
	Categories  []CategoryInfo               `json:"categories"`
	Targets     []TargetInfo                 `json:"targets"`
	Rows        []Row                        `json:"rows"`
	Regions     []RegionInfo                 `json:"regions"`
	Cells       map[string]map[string]Cell   `json:"cells"`
	Timeline    map[string][]Day             `json:"timeline"`
	Events      map[string][]Event           `json:"events"`
	I18n        map[string]map[string]string `json:"i18n"`
	Repo        string                       `json:"repo"`
}

// CategoryInfo names a category.
type CategoryInfo struct {
	ID    string            `json:"id"`
	Title map[string]string `json:"title"`
}

// TargetInfo names a target.
type TargetInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`
}

// Row is one network (ASN × region × connection type).
type Row struct {
	Key     string `json:"key"`
	ASN     int    `json:"asn"`
	ISP     string `json:"isp"`
	Region  string `json:"region,omitempty"`
	Conn    string `json:"conn"`
	Reports int    `json:"reports"`
	Last    string `json:"last"`
}

// RegionInfo names a region.
type RegionInfo struct {
	Code string `json:"code"`
	RU   string `json:"ru"`
	EN   string `json:"en"`
}

// Cell is the latest state of one target on one network.
type Cell struct {
	Status model.Status     `json:"s"`
	Kind   model.Kind       `json:"k"`
	Conf   model.Confidence `json:"c,omitempty"`
	Date   string           `json:"d"`
	N      int              `json:"n"`
}

// Day is [date, ok, throttled, partial, blocked] counts.
type Day [5]any

// Event is a status change of a target on a network.
type Event struct {
	Date string       `json:"d"`
	Row  string       `json:"row"`
	From model.Status `json:"from"`
	To   model.Status `json:"to"`
	Kind model.Kind   `json:"k"`
}

// TimelineDays bounds the timeline length.
const TimelineDays = 120

// statusRank orders statuses from best to worst; ties resolve to the worse one.
func statusRank(s model.Status) int {
	switch s {
	case model.StatusOK:
		return 0
	case model.StatusThrottled:
		return 1
	case model.StatusPartial:
		return 2
	case model.StatusBlocked:
		return 3
	}
	return -1
}

func rowKey(asn int, region, conn string) string {
	return fmt.Sprintf("%d|%s|%s", asn, region, conn)
}

type obs struct {
	date   string
	status model.Status
	kind   model.Kind
	conf   model.Confidence
}

// Aggregate builds the map data from valid submissions.
func Aggregate(entries []Entry, cat *catalog.Catalog, now time.Time) *Data {
	// Empty slices (not nil) so the JSON has [] instead of null: the
	// front-end must work before the first submission arrives.
	d := &Data{
		Generated:  now.UTC().Format(time.RFC3339),
		Categories: []CategoryInfo{},
		Targets:    []TargetInfo{},
		Rows:       []Row{},
		Regions:    []RegionInfo{},
		Cells:      map[string]map[string]Cell{},
		Timeline:   map[string][]Day{},
		Events:     map[string][]Event{},
	}
	rows := map[string]*Row{}
	series := map[string]map[string][]obs{} // row -> target -> observations (date order)
	days := map[string]map[string]*[4]int{} // target -> date -> counts
	seenTargets := map[string]bool{}
	regions := map[string]bool{}

	for _, e := range entries {
		s := e.Sub
		d.Submissions++
		if s.Date > d.Updated {
			d.Updated = s.Date
		}
		key := rowKey(s.Network.ASN, s.Network.Region, s.Network.Conn)
		r := rows[key]
		if r == nil {
			r = &Row{Key: key, ASN: s.Network.ASN, Region: s.Network.Region, Conn: s.Network.Conn}
			rows[key] = r
		}
		r.Reports++
		if s.Date >= r.Last {
			r.Last = s.Date
			if s.Network.ISP != "" {
				r.ISP = s.Network.ISP
			}
		}
		if s.Network.Region != "" {
			regions[s.Network.Region] = true
		}
		if series[key] == nil {
			series[key] = map[string][]obs{}
		}
		for _, res := range s.Results {
			if res.Status == model.StatusUnknown {
				continue
			}
			seenTargets[res.Target] = true
			series[key][res.Target] = append(series[key][res.Target], obs{s.Date, res.Status, res.Kind, res.Confidence})
			if days[res.Target] == nil {
				days[res.Target] = map[string]*[4]int{}
			}
			c := days[res.Target][s.Date]
			if c == nil {
				c = &[4]int{}
				days[res.Target][s.Date] = c
			}
			if i := statusRank(res.Status); i >= 0 {
				c[i]++
			}
		}
	}

	// Cells and events.
	for key, byTarget := range series {
		for target, list := range byTarget {
			sort.SliceStable(list, func(i, j int) bool { return list[i].date < list[j].date })
			daily := dailyStatus(list)
			last := daily[len(daily)-1]
			if d.Cells[key] == nil {
				d.Cells[key] = map[string]Cell{}
			}
			d.Cells[key][target] = Cell{Status: last.status, Kind: last.kind, Conf: last.conf, Date: last.date, N: len(list)}
			for i := 1; i < len(daily); i++ {
				if daily[i].status != daily[i-1].status {
					d.Events[target] = append(d.Events[target], Event{Date: daily[i].date, Row: key, From: daily[i-1].status, To: daily[i].status, Kind: daily[i].kind})
				}
			}
		}
	}
	for t := range d.Events {
		ev := d.Events[t]
		sort.Slice(ev, func(i, j int) bool {
			if ev[i].Date != ev[j].Date {
				return ev[i].Date > ev[j].Date
			}
			return ev[i].Row < ev[j].Row
		})
		if len(ev) > 200 {
			ev = ev[:200]
		}
		d.Events[t] = ev
	}

	// Timeline (last TimelineDays days with data).
	cutoff := now.AddDate(0, 0, -TimelineDays).Format("2006-01-02")
	for target, byDate := range days {
		var dates []string
		for date := range byDate {
			if date >= cutoff {
				dates = append(dates, date)
			}
		}
		sort.Strings(dates)
		for _, date := range dates {
			c := byDate[date]
			d.Timeline[target] = append(d.Timeline[target], Day{date, c[0], c[1], c[2], c[3]})
		}
	}

	// Rows sorted by reports, then ASN.
	for _, r := range rows {
		if r.ISP == "" {
			r.ISP = fmt.Sprintf("AS%d", r.ASN)
		}
		d.Rows = append(d.Rows, *r)
	}
	sort.Slice(d.Rows, func(i, j int) bool {
		if d.Rows[i].Reports != d.Rows[j].Reports {
			return d.Rows[i].Reports > d.Rows[j].Reports
		}
		return d.Rows[i].Key < d.Rows[j].Key
	})

	// Targets and categories in catalog order; unknown targets last.
	known := map[string]bool{}
	if cat != nil {
		for _, c := range cat.Categories {
			used := false
			for _, t := range c.Targets {
				if seenTargets[t.ID] {
					d.Targets = append(d.Targets, TargetInfo{ID: t.ID, Name: displayName(t), Category: c.ID})
					known[t.ID] = true
					used = true
				}
			}
			if used {
				d.Categories = append(d.Categories, CategoryInfo{ID: c.ID, Title: c.Title})
			}
		}
	}
	var unknown []string
	for t := range seenTargets {
		if !known[t] {
			unknown = append(unknown, t)
		}
	}
	sort.Strings(unknown)
	if len(unknown) > 0 {
		d.Categories = append(d.Categories, CategoryInfo{ID: "other", Title: map[string]string{"ru": "Другое", "en": "Other"}})
		for _, t := range unknown {
			d.Targets = append(d.Targets, TargetInfo{ID: t, Name: t, Category: "other"})
		}
	}

	for code := range regions {
		ri := RegionInfo{Code: code, RU: code, EN: code}
		if r := netinfo.RegionByCode(code); r != nil {
			ri.RU, ri.EN = r.RU, r.EN
		}
		d.Regions = append(d.Regions, ri)
	}
	sort.Slice(d.Regions, func(i, j int) bool { return d.Regions[i].RU < d.Regions[j].RU })
	return d
}

func displayName(t catalog.Target) string {
	if t.Name != "" {
		return t.Name
	}
	return t.ID
}

// dailyStatus collapses observations to one per day: the majority status of
// that day, with ties resolved towards the worse status.
func dailyStatus(list []obs) []obs {
	var out []obs
	for i := 0; i < len(list); {
		j := i
		counts := map[model.Status]int{}
		kinds := map[model.Status]obs{}
		for j < len(list) && list[j].date == list[i].date {
			counts[list[j].status]++
			kinds[list[j].status] = list[j]
			j++
		}
		var best model.Status
		bestN := -1
		for s, n := range counts {
			if n > bestN || (n == bestN && statusRank(s) > statusRank(best)) {
				best, bestN = s, n
			}
		}
		out = append(out, kinds[best])
		i = j
	}
	return out
}

// I18nFrom extracts the strings the map needs from the locale catalogs.
func I18nFrom(keys map[string]map[string]string) map[string]map[string]string {
	out := map[string]map[string]string{}
	for lang, kv := range keys {
		m := map[string]string{}
		for k, v := range kv {
			if strings.HasPrefix(k, "map.") || strings.HasPrefix(k, "status.") || strings.HasPrefix(k, "conn.") ||
				strings.HasPrefix(k, "summary.") || (strings.HasPrefix(k, "kind.") && strings.HasSuffix(k, ".title")) ||
				k == "app.tagline" {
				m[k] = v
			}
		}
		out[lang] = m
	}
	return out
}
